use super::*;

mod balanced_scanner;
use balanced_scanner::scan_balanced_json;
#[cfg(test)]
pub(crate) use balanced_scanner::{
    BalancedJsonScanStats, MAX_BALANCED_CANDIDATES, MAX_BALANCED_CANDIDATE_BYTES,
};

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
    ensure_text_parse_budget(text)?;
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
    for candidate in scan_balanced_json(candidate).candidates {
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
    parse_last_fenced_json_with_stats(text).value
}

fn parse_last_fenced_json_with_stats(text: &str) -> FencedJsonParse {
    let mut rest = text;
    let mut last_ok: Option<Value> = None;
    #[cfg(test)]
    let mut candidate_count = 0usize;
    #[cfg(test)]
    let mut parsed_candidate_bytes = 0usize;
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
        #[cfg(test)]
        {
            candidate_count += 1;
            parsed_candidate_bytes += body.len();
        }
        if let Ok(value) = serde_json::from_str::<Value>(body) {
            last_ok = Some(value);
        }
        let consumed = (body_start.as_ptr() as usize - rest.as_ptr() as usize) + close_off + 3;
        rest = &rest[consumed..];
    }
    FencedJsonParse {
        value: last_ok,
        #[cfg(test)]
        stats: FencedJsonScanStats {
            inspected_bytes: text.len(),
            candidate_count,
            parsed_candidate_bytes,
        },
    }
}

struct FencedJsonParse {
    value: Option<Value>,
    #[cfg(test)]
    stats: FencedJsonScanStats,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FencedJsonScanStats {
    pub(crate) inspected_bytes: usize,
    pub(crate) candidate_count: usize,
    pub(crate) parsed_candidate_bytes: usize,
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

pub(crate) fn balanced_json_slices(text: &str) -> Result<Vec<&str>> {
    ensure_text_parse_budget(text)?;
    Ok(scan_balanced_json(text)
        .candidates
        .into_iter()
        .map(|candidate| candidate.slice)
        .collect())
}

#[cfg(test)]
pub(crate) fn balanced_json_scan_stats(text: &str) -> BalancedJsonScanStats {
    scan_balanced_json(text).stats
}

#[cfg(test)]
pub(crate) fn fenced_json_scan_stats(text: &str) -> FencedJsonScanStats {
    parse_last_fenced_json_with_stats(text).stats
}
