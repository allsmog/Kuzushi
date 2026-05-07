use anyhow::{Context, Result};
use serde_json::Value;

use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentStructuredOutput};

#[derive(Debug, Clone)]
pub(crate) struct StructuredJsonContract {
    pub(crate) tool_name: String,
    pub(crate) schema_name: String,
    pub(crate) schema: Value,
}

impl StructuredJsonContract {
    pub(crate) fn new(
        tool_name: impl Into<String>,
        schema_name: impl Into<String>,
        schema: Value,
    ) -> Self {
        Self {
            tool_name: tool_name.into(),
            schema_name: schema_name.into(),
            schema,
        }
    }

    fn runtime_contract(&self) -> AgentStructuredOutput {
        AgentStructuredOutput::json_schema(self.schema_name.clone(), self.schema.clone())
    }
}

pub(crate) fn query_required_structured_json<T>(
    runtime: &dyn AgentRuntime,
    request: AgentQueryRequest,
    contract: StructuredJsonContract,
    validate: impl Fn(Value) -> Result<T>,
) -> Result<T> {
    let request = request.with_structured_output(contract.runtime_contract());
    let response = runtime.query_blocking(request.clone())?;
    parse_or_repair_required_structured_json(
        response,
        contract,
        validate,
        |repair_prompt, output| {
            runtime.query_blocking(
                AgentQueryRequest::new(
                    request.model.clone(),
                    request.cwd.clone(),
                    request.system_prompt.clone(),
                    repair_prompt,
                )
                .with_tool_policy(request.tool_policy.clone())
                .with_structured_output(output),
            )
        },
    )
}

pub(crate) fn parse_or_repair_required_structured_json<T>(
    response: AgentQueryResponse,
    contract: StructuredJsonContract,
    validate: impl Fn(Value) -> Result<T>,
    repair: impl FnOnce(String, AgentStructuredOutput) -> Result<AgentQueryResponse>,
) -> Result<T> {
    match parse_and_validate(&response, &contract, &validate) {
        Ok(value) => Ok(value),
        Err(initial_error) => {
            let raw = raw_agent_response(&response);
            let repair_response = repair(
                build_repair_prompt(&contract, &raw, &initial_error.to_string()),
                contract.runtime_contract(),
            )?;
            parse_and_validate(&repair_response, &contract, &validate).with_context(|| {
                let repair_raw = raw_agent_response(&repair_response);
                format!(
                    "{tool} could not satisfy structured JSON contract `{schema}` after one repair pass.\n\
                     Initial parse/validation failure: {initial_error}\n\
                     Repair parse/validation failure is above.\n\
                     Raw initial model response:\n{raw}\n\
                     Raw repair model response:\n{repair_raw}",
                    tool = contract.tool_name,
                    schema = contract.schema_name,
                )
            })
        }
    }
}

fn parse_and_validate<T>(
    response: &AgentQueryResponse,
    contract: &StructuredJsonContract,
    validate: &impl Fn(Value) -> Result<T>,
) -> Result<T> {
    let value = structured_json_value(response, contract)?;
    validate(value)
}

pub(crate) fn structured_json_value(
    response: &AgentQueryResponse,
    contract: &StructuredJsonContract,
) -> Result<Value> {
    if let Some(value) = response.structured.clone() {
        return Ok(value);
    }
    parse_json_value_from_agent_text(&response.text).with_context(|| {
        format!(
            "{} expected pi-agent-core to return JSON for `{}`",
            contract.tool_name, contract.schema_name
        )
    })
}

pub(crate) fn parse_json_value_from_agent_text(text: &str) -> Result<Value> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        anyhow::bail!("model response was empty");
    }
    let candidate = strip_markdown_fence(trimmed);
    if let Ok(value) = serde_json::from_str::<Value>(candidate) {
        return Ok(value);
    }

    let mut saw_json_like_text = false;
    for slice in balanced_json_slices(candidate, '{', '}')
        .into_iter()
        .chain(balanced_json_slices(candidate, '[', ']'))
    {
        saw_json_like_text = true;
        if let Ok(value) = serde_json::from_str::<Value>(slice) {
            return Ok(value);
        }
    }
    if saw_json_like_text {
        anyhow::bail!("model response contained JSON-looking text, but it was invalid");
    }
    anyhow::bail!("model response did not contain a JSON object or array")
}

fn strip_markdown_fence(text: &str) -> &str {
    let Some(without_open) = text.strip_prefix("```") else {
        return text;
    };
    let without_lang = without_open
        .strip_prefix("json")
        .or_else(|| without_open.strip_prefix("JSON"))
        .unwrap_or(without_open)
        .trim_start();
    without_lang
        .strip_suffix("```")
        .map(str::trim)
        .unwrap_or(text)
}

fn balanced_json_slices(text: &str, open: char, close: char) -> Vec<&str> {
    let mut slices = Vec::new();
    for (start, ch) in text.char_indices() {
        if ch != open {
            continue;
        }
        let mut depth = 0usize;
        let mut in_string = false;
        let mut escaped = false;
        for (offset, current) in text[start..].char_indices() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if current == '\\' {
                    escaped = true;
                } else if current == '"' {
                    in_string = false;
                }
                continue;
            }
            match current {
                '"' => in_string = true,
                c if c == open => depth += 1,
                c if c == close => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        let end = start + offset + current.len_utf8();
                        slices.push(&text[start..end]);
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    slices
}

fn raw_agent_response(response: &AgentQueryResponse) -> String {
    match &response.structured {
        Some(structured) if response.text.trim().is_empty() => {
            serde_json::to_string_pretty(structured).unwrap_or_else(|_| structured.to_string())
        }
        Some(structured) => format!(
            "structured:\n{}\n\ntext:\n{}",
            serde_json::to_string_pretty(structured).unwrap_or_else(|_| structured.to_string()),
            response.text
        ),
        None => response.text.clone(),
    }
}

fn build_repair_prompt(
    contract: &StructuredJsonContract,
    raw_response: &str,
    parse_error: &str,
) -> String {
    let schema = serde_json::to_string_pretty(&contract.schema)
        .unwrap_or_else(|_| contract.schema.to_string());
    format!(
        "The previous model response for `{tool}` did not satisfy `{schema_name}`.\n\n\
         Parse/validation failure:\n{parse_error}\n\n\
         Required JSON schema:\n{schema}\n\n\
         Raw invalid model response:\n{raw_response}\n\n\
         Return only one valid JSON value matching `{schema_name}`. Do not include markdown fences or prose.",
        tool = contract.tool_name,
        schema_name = contract.schema_name,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_first_parseable_balanced_json_without_using_last_brace_in_prose() {
        let parsed =
            parse_json_value_from_agent_text("before {not json} then {\"ok\":true} after }")
                .unwrap();
        assert_eq!(parsed["ok"], true);
    }

    #[test]
    fn parses_json_fence() {
        let parsed = parse_json_value_from_agent_text("```json\n{\"ok\":true}\n```").unwrap();
        assert_eq!(parsed["ok"], true);
    }
}
