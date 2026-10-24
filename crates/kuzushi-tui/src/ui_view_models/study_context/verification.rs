//! Keep recorded checks ahead of potentially long model-authored context.
use serde_json::Value;

pub(super) fn lines(document: &Value) -> Vec<String> {
    let Some(check) = document.get("verification") else {
        return Vec::new();
    };
    let verdict = check["verdict"]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("unrecorded");
    let mut lines = vec![format!("Recorded grounding: {verdict}.")];
    if let Some(reason) = check["groundingDegraded"].as_str() {
        lines.push(format!("Coverage limitation: {reason}"));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn failed_checks_stay_failed_when_catalog_coverage_is_partial() {
        let text = lines(
            &json!({"verification":{"verdict":"failed","groundingSource":"partial-catalog","groundingDegraded":"Unseen entry points remain unknown."}}),
        );
        assert_eq!(text[0], "Recorded grounding: failed.");
        assert!(text[1].contains("Unseen entry points remain unknown"));
        assert!(!text.join(" ").contains("verified"));
    }

    #[test]
    fn legacy_absence_and_malformed_checks_never_invent_verified_coverage() {
        assert!(lines(&json!({})).is_empty());
        assert_eq!(
            lines(&json!({"verification":null})),
            vec!["Recorded grounding: unrecorded."]
        );
    }
}
