use super::*;
use crate::config::V2Config;
use crate::findings::test_support::ReviewedFindingFixture;
use crate::findings::{ReviewDecisionVerdict, TriageAuthor};

/// Run `variant:hunt` without a runtime: a finding the review gate admits
/// reaches the runtime requirement, one it refuses returns a refusal.
fn hunt_without_runtime(fixture: &ReviewedFindingFixture) -> Result<Value> {
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&fixture.workspace),
        findings_store: Some(&fixture.store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    run_variant_hunt(
        json!({"fingerprint": fixture.finding().fingerprint}),
        &ctx,
        None,
    )
}

#[test]
fn human_confirmed_finding_without_triage_passes_the_review_gate() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_human_decision(ReviewDecisionVerdict::Confirmed);

    let error = hunt_without_runtime(&fixture).unwrap_err().to_string();

    assert!(error.contains("variant:hunt"), "{error}");
    assert!(!error.contains("triage"), "{error}");
}

#[test]
fn human_rejection_overrides_automated_true_positive() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_auto_triage(TriageVerdict::TruePositive);
    fixture.record_human_decision(ReviewDecisionVerdict::RejectedFalsePositive);

    let result = hunt_without_runtime(&fixture).unwrap();

    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["data"]["reason"], json!("non-true-positive"));
    assert_eq!(result["data"]["verdict"], json!("false_positive"));
    assert_eq!(result["data"]["reviewAuthor"], json!("human"));
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("has review decision \"rejected_false_positive\" by human"));
}

#[test]
fn unreviewed_finding_refuses_with_both_remedies() {
    let fixture = ReviewedFindingFixture::new();

    let result = hunt_without_runtime(&fixture).unwrap();

    assert_eq!(result["data"]["reason"], json!("missing-triage"));
    assert!(result["output"].as_str().unwrap().contains(
        "no triage verdict and no confirming review decision. Run triage:run first, or record a confirmed or to_fix review decision."
    ));
}

#[test]
fn hunt_prompt_presents_a_human_confirmation_as_a_review_decision() {
    let fixture = ReviewedFindingFixture::new();
    let decision = ReviewDecision {
        verdict: ReviewDecisionVerdict::Confirmed,
        author: TriageAuthor::Human,
        confidence: 1.0,
        rationale: "operator confirmed".to_string(),
        dismiss_reason: None,
        actor: Some("operator".to_string()),
    };

    let prompt = build_variant_hunt_prompt(
        &fixture.finding(),
        &ReviewConfirmation::ReviewDecision(decision),
        false,
        &[],
    );

    assert!(prompt.contains("Review decision:\nVerdict: confirmed\nAuthor: human"));
    assert!(!prompt.contains("Triage assessment:"));
}
