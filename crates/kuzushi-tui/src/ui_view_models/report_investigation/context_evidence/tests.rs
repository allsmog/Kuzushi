use super::*;
use serde_json::json;

#[test]
fn grouping_retains_partial_missing_and_distinct_unavailable_context() {
    let states = [
        json!({"status":"recorded","verification":{"verdict":"verified"}}),
        json!({"status":"recorded","verification":{"verdict":"verified"}}),
        json!({"status":"recorded","verification":{"verdict":"partial","groundingDegraded":"Inspection was capped."}}),
        json!({"status":"unavailable","message":"First retained source is missing."}),
        json!({"status":"unavailable","message":"Second source failed authentication."}),
        json!({}),
    ];
    let labels = ["One", "Two", "Three", "Four", "Five", "Six"];
    let before = states.clone();
    let overview =
        case_lines(labels.into_iter().zip(states.iter()), false, "boundaries").join("\n");
    for expected in [
        "Context grounding: verified. · 2 boundaries",
        "Three: Context grounding: partial.",
        "Four: Context evidence: unavailable.",
        "Five: Context evidence: unavailable.",
        "Six: Context evidence: not recorded.",
        "First retained source is missing.",
        "Second source failed authentication.",
    ] {
        assert!(overview.contains(expected), "{expected}: {overview}");
    }
    let details = case_lines(labels.into_iter().zip(states.iter()), true, "boundaries").join("\n");
    assert!(details.contains("One: Context grounding: verified."));
    assert!(details.contains("Two: Context grounding: verified."));
    assert!(details.contains("Inspection was capped."));
    assert!(details.contains("Six: Context evidence: not recorded."));
    assert_eq!(states, before);
}

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
