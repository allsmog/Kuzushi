use crate::capabilities::uaf_hunt::application::normalize_uaf_hunt_findings;
use crate::capabilities::uaf_hunt::domain::UafHuntInput;
use crate::findings::Finding;
use crate::runtime::AgentLoopOutcome;
use anyhow::Result;
use serde_json::Value;

pub(super) fn extract_findings(
    outcome: &AgentLoopOutcome,
    options: &UafHuntInput,
) -> Result<Vec<Finding>> {
    if let Some(structured) = outcome.structured.as_ref() {
        return normalize_uaf_hunt_findings(structured, options.max_findings);
    }
    extract_findings_from_text(outcome, options)
}

fn extract_findings_from_text(
    outcome: &AgentLoopOutcome,
    options: &UafHuntInput,
) -> Result<Vec<Finding>> {
    if outcome.truncated {
        return Ok(Vec::new());
    }
    parse_findings_text(&outcome.text, options.max_findings)
}

fn parse_findings_text(text: &str, max_findings: usize) -> Result<Vec<Finding>> {
    let text = text.trim();
    if text.is_empty() {
        anyhow::bail!("uaf-hunt output parse failed: agent returned no findings envelope");
    }
    let parsed = serde_json::from_str::<Value>(text)
        .ok()
        .or_else(|| extract_first_json_object(text))
        .ok_or_else(|| anyhow::anyhow!("uaf-hunt output parse failed: no valid JSON object"))?;
    normalize_uaf_hunt_findings(&parsed, max_findings)
}

fn extract_first_json_object(text: &str) -> Option<Value> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end <= start {
        return None;
    }
    serde_json::from_str(&text[start..=end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn first_json_object_parser_recovers_balanced_object_from_prose() {
        let parsed = extract_first_json_object("before {\"findings\":[]} after").unwrap();
        assert_eq!(parsed["findings"], json!([]));
        assert!(extract_first_json_object("no object").is_none());
        assert!(extract_first_json_object("} before {").is_none());
    }

    #[test]
    fn missing_or_malformed_text_cannot_look_like_a_clean_hunt() {
        for text in ["", "agent stopped without an envelope", "before {broken} after"] {
            let error = parse_findings_text(text, 10).unwrap_err().to_string();
            assert!(error.contains("output parse failed"), "{error}");
        }
    }
}
