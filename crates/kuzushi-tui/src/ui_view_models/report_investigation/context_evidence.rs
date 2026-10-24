//! Display historical context limitations independently of completed scan work.
use super::*;
use serde_json::Value;

pub(super) fn lines(document: &InvestigationReportDocument, details: bool) -> Vec<String> {
    match document {
        InvestigationReportDocument::Study(receipt) => {
            state_lines(&receipt.scope["contextEvidence"], details)
        }
        InvestigationReportDocument::ScopeStudy(receipt) => receipt
            .cases
            .iter()
            .flat_map(|case| {
                named_lines(
                    &case.label,
                    &receipt.scope[&case.id]["contextEvidence"],
                    details,
                )
            })
            .collect(),
        InvestigationReportDocument::ContextMatrix(receipt) => receipt
            .cases
            .iter()
            .flat_map(|case| {
                named_lines(
                    &case.label,
                    &receipt.scope["caseContextEvidence"][&case.id],
                    details,
                )
            })
            .collect(),
    }
}

fn named_lines(label: &str, state: &Value, details: bool) -> Vec<String> {
    let mut lines = state_lines(state, details);
    if let Some(first) = lines.first_mut() {
        *first = format!("{label}: {first}");
    }
    lines
}

fn state_lines(state: &Value, details: bool) -> Vec<String> {
    match state["status"].as_str() {
        Some("recorded") => recorded_lines(state, details),
        Some("omitted") => vec!["Context: explicitly omitted.".into()],
        Some("unbound") => vec!["Context: no explicit historical reference recorded.".into()],
        Some("unavailable") => vec![
            "Context evidence: unavailable.".into(),
            state["message"]
                .as_str()
                .unwrap_or("Recorded context could not be read.")
                .into(),
        ],
        _ => Vec::new(),
    }
}

fn recorded_lines(state: &Value, details: bool) -> Vec<String> {
    let verification = &state["verification"];
    let verdict = verification["verdict"].as_str().unwrap_or("unrecorded");
    let mut lines = vec![format!("Context grounding: {verdict}.")];
    if !details {
        return lines;
    }
    if let Some(reason) = verification["groundingDegraded"].as_str() {
        lines.push(format!("Context limitation: {reason}"));
    }
    lines.extend(super::super::study_context::context_source_receipt_lines(
        &state["sourceContext"],
    ));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn partial_context_stays_visible_and_details_keep_the_recorded_reason() {
        let state = json!({"status":"recorded","verification":{"verdict":"partial","groundingSource":"partial-catalog","groundingDegraded":"Per-file inspection was capped; unseen entry points remain unknown."}});
        assert_eq!(
            state_lines(&state, false),
            vec!["Context grounding: partial."]
        );
        let detail = state_lines(&state, true).join("\n");
        assert!(detail.contains("inspection was capped") && detail.contains("unknown"));
        assert!(!detail.contains("verified"));
    }

    #[test]
    fn missing_legacy_verification_does_not_claim_grounding_or_current_context() {
        assert!(state_lines(&json!({}), true).is_empty());
        assert_eq!(
            state_lines(&json!({"status":"recorded"}), false),
            vec!["Context grounding: unrecorded."]
        );
        let unavailable = state_lines(&json!({"status":"unavailable","message":"Exact historical context is missing. No active revision substituted."}), true).join("\n");
        assert!(
            unavailable.contains("unavailable")
                && unavailable.contains("No active revision substituted")
        );
    }

    #[test]
    fn report_details_show_source_receipt_without_context_reader_shortcuts() {
        let state = json!({"status":"recorded","sourceContext":{"scopeContext":{"status":"recorded",
            "receipt":{"schemaVersion":1,"selectedFileCount":3,"sourcePartial":false,"completeRepositoryCoverage":false,
                "sourceEvidence":{"files":[],"omissions":{}}}}}});
        let text = state_lines(&state, true).join("\n");
        assert!(text.contains("FILE-GROUP CONTEXT RECEIPT") && text.contains("Requested files: 3"));
        assert!(!text.contains("Tab reads"));
        assert_eq!(
            state_lines(&json!({"status":"omitted"}), false),
            vec!["Context: explicitly omitted."]
        );
    }
}
