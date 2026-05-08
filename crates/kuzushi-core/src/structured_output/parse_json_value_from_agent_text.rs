use super::*;

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

pub(crate) fn strip_markdown_fence(text: &str) -> &str {
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

pub(crate) fn balanced_json_slices(text: &str, open: char, close: char) -> Vec<&str> {
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

pub(crate) fn raw_agent_response(response: &AgentQueryResponse) -> String {
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

pub(crate) fn build_repair_prompt(
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
