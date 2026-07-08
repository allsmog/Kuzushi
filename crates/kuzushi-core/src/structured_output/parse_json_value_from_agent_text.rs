use super::*;

#[cfg(test)]
pub(crate) fn parse_json_value_from_agent_text(text: &str) -> Result<Value> {
    Ok(parse_json_value_from_agent_text_with_strategy(text)?.value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JsonExtractionStrategy {
    Direct,
    LastFencedBlock,
    BalancedObject,
    BalancedArray,
}

impl JsonExtractionStrategy {
    fn is_balanced(self) -> bool {
        matches!(self, Self::BalancedObject | Self::BalancedArray)
    }

    #[cfg(test)]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::LastFencedBlock => "last_fenced_block",
            Self::BalancedObject => "balanced_object",
            Self::BalancedArray => "balanced_array",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ParsedAgentJson {
    pub(crate) value: Value,
    pub(crate) strategy: JsonExtractionStrategy,
}

pub(crate) fn parse_json_value_from_agent_text_with_strategy(
    text: &str,
) -> Result<ParsedAgentJson> {
    let trimmed = non_empty_agent_text(text)?;
    let candidate = strip_markdown_fence(trimmed);
    parse_direct_agent_json(candidate)
        .or_else(|| parse_last_fenced_agent_json(text))
        .map(Ok)
        .unwrap_or_else(|| parse_balanced_agent_json(candidate))
}

fn non_empty_agent_text(text: &str) -> Result<&str> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        anyhow::bail!("model response was empty");
    }
    Ok(trimmed)
}

fn parse_direct_agent_json(candidate: &str) -> Option<ParsedAgentJson> {
    Some(ParsedAgentJson {
        value: serde_json::from_str::<Value>(candidate).ok()?,
        strategy: JsonExtractionStrategy::Direct,
    })
}

fn parse_last_fenced_agent_json(text: &str) -> Option<ParsedAgentJson> {
    Some(ParsedAgentJson {
        value: parse_last_fenced_json(text)?,
        strategy: JsonExtractionStrategy::LastFencedBlock,
    })
}

fn parse_balanced_agent_json(candidate: &str) -> Result<ParsedAgentJson> {
    let mut saw_json_like_text = false;
    for candidate in balanced_json_candidates(candidate) {
        saw_json_like_text = true;
        if let Ok(value) = serde_json::from_str::<Value>(candidate.slice) {
            return Ok(ParsedAgentJson {
                value,
                strategy: candidate.strategy,
            });
        }
    }
    Err(balanced_json_parse_error(saw_json_like_text))
}

struct BalancedJsonCandidate<'a> {
    strategy: JsonExtractionStrategy,
    slice: &'a str,
}

fn balanced_json_candidates(text: &str) -> Vec<BalancedJsonCandidate<'_>> {
    let mut candidates = Vec::new();
    append_reversed_balanced_candidates(
        &mut candidates,
        text,
        '{',
        '}',
        JsonExtractionStrategy::BalancedObject,
    );
    append_reversed_balanced_candidates(
        &mut candidates,
        text,
        '[',
        ']',
        JsonExtractionStrategy::BalancedArray,
    );
    candidates
}

fn append_reversed_balanced_candidates<'a>(
    candidates: &mut Vec<BalancedJsonCandidate<'a>>,
    text: &'a str,
    open: char,
    close: char,
    strategy: JsonExtractionStrategy,
) {
    let mut slices = balanced_json_slices(text, open, close);
    slices.reverse();
    candidates.extend(
        slices
            .into_iter()
            .map(|slice| BalancedJsonCandidate { strategy, slice }),
    );
}

fn balanced_json_parse_error(saw_json_like_text: bool) -> anyhow::Error {
    if saw_json_like_text {
        anyhow::anyhow!(
            "model response contained JSON-looking text, but it was invalid; strategies attempted: direct,last_fenced_block,balanced_object,balanced_array"
        )
    } else {
        anyhow::anyhow!(
            "model response did not contain a JSON object or array; strategies attempted: direct,last_fenced_block,balanced_object,balanced_array"
        )
    }
}

/// Locate every ```json … ``` (or bare ``` … ```) block in `text`, parse
/// each as a JSON Value, return the last one that parses. Anthropic /
/// Sonnet typically emit the verdict in the FINAL fenced block; older
/// reasoning traces above it can contain C code with unbalanced braces
/// that would defeat the simple `find('{')..rfind('}')` approach.
fn parse_last_fenced_json(text: &str) -> Option<Value> {
    let mut rest = text;
    let mut last_ok: Option<Value> = None;
    while let Some(open_pos) = rest.find("```") {
        let after_ticks = &rest[open_pos + 3..];
        // Optional `json` (or `JSON`) tag right after the opening fence.
        let body_start = after_ticks
            .strip_prefix("json")
            .or_else(|| after_ticks.strip_prefix("JSON"))
            .unwrap_or(after_ticks);
        let body_start = body_start.trim_start_matches('\n').trim_start_matches(' ');
        let Some(close_off) = body_start.find("```") else {
            break;
        };
        let body = body_start[..close_off].trim();
        if let Ok(value) = serde_json::from_str::<Value>(body) {
            last_ok = Some(value);
        }
        let consumed = (body_start.as_ptr() as usize - rest.as_ptr() as usize) + close_off + 3;
        rest = &rest[consumed..];
    }
    last_ok
}

/// Typed convenience wrapper: parse the agent's text as a JSON Value, then
/// deserialise into T. Balanced-brace extraction is refused for typed verdicts
/// because those snippets can come from reasoning prose rather than the final
/// answer.
pub(crate) fn try_parse_typed_from_agent_text<T: serde::de::DeserializeOwned>(
    text: &str,
) -> Option<T> {
    let parsed = parse_json_value_from_agent_text_with_strategy(text).ok()?;
    if parsed.strategy.is_balanced() {
        eprintln!(
            "refusing typed verdict parse from {:?} extraction; response needs explicit JSON",
            parsed.strategy
        );
        return None;
    }
    serde_json::from_value::<T>(parsed.value).ok()
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
