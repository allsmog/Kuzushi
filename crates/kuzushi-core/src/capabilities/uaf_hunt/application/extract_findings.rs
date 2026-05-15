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
    if outcome.text.is_empty() {
        return Ok(Vec::new());
    }
    if let Ok(parsed) = serde_json::from_str::<Value>(outcome.text.trim()) {
        return normalize_uaf_hunt_findings(&parsed, options.max_findings);
    }
    extract_first_json_object(&outcome.text)
        .map(|parsed| normalize_uaf_hunt_findings(&parsed, options.max_findings))
        .unwrap_or_else(|| Ok(Vec::new()))
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
}
