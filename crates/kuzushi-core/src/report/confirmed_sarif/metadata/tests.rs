use super::*;
mod dispatch;
use crate::findings::{
    FindingStore, ReviewDecision, ReviewDecisionVerdict, Severity, TriageAuthor,
};

#[test]
fn historical_confirmation_exports_its_author_reason_and_unknown_source() {
    let store = FindingStore::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    store
        .record_run_started("owned-run", root.path(), "running")
        .unwrap();
    let finding = Finding::new_semgrep(
        "owned-observation",
        "main.rs",
        1,
        None,
        Severity::Low,
        "Labeled observation, no security claim",
    );
    let id = store.insert_finding("owned-run", &finding).unwrap();
    store
        .append_user_review_decision(
            id,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Confirmed,
                author: TriageAuthor::Human,
                confidence: 0.7,
                rationale: "Owned metadata check".into(),
                dismiss_reason: None,
                actor: Some("operator".into()),
            },
        )
        .unwrap();
    let findings = store.list_all_findings().unwrap();
    let decisions = store.list_review_decisions_for_findings(&findings).unwrap();
    let mut document = json!({"runs":[{"properties":{},"results":[{"properties":{}}]}]});
    attach_export_metadata(&mut document, &findings, &decisions, &[], false).unwrap();
    assert_eq!(
        document["runs"][0]["properties"]["kuzushiExport"]["scope"],
        "workspace_history"
    );
    let properties = &document["runs"][0]["results"][0]["properties"];
    assert_eq!(properties["kuzushiReviewDecision"], "confirmed");
    assert_eq!(properties["kuzushiReviewDecisionAuthor"], "human");
    assert_eq!(
        properties["kuzushiReviewDecisionReason"],
        "Owned metadata check"
    );
    assert!(properties["kuzushiReviewDecisionBasis"].is_null());
    assert!(properties["kuzushiSourceApplicability"].is_null());
}

#[test]
fn suppression_state_is_independent_of_recorded_confirmation() {
    let mut finding = Finding::new_semgrep(
        "owned-observation",
        "main.rs",
        1,
        None,
        Severity::Low,
        "Labeled observation",
    );
    finding.suppressed = true;
    let mut document = json!({"runs":[{"properties":{},"results":[{"properties":{}}]}]});
    attach_export_metadata(&mut document, &[finding], &[], &[], true).unwrap();
    assert_eq!(
        document["runs"][0]["properties"]["kuzushiExport"]["scope"],
        "investigation"
    );
    assert_eq!(
        document["runs"][0]["results"][0]["properties"]["kuzushiSuppressed"],
        true
    );
    assert!(document
        .to_string()
        .contains("Missing observations do not establish a fix"));
}
