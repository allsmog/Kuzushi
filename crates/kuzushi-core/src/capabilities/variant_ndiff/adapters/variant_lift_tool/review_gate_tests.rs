use super::*;
use crate::findings::test_support::ReviewedFindingFixture;
use crate::findings::ReviewDecisionVerdict;
use crate::V2Config;

fn lift(fixture: &ReviewedFindingFixture) -> Result<Value> {
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&fixture.workspace),
        findings_store: Some(&fixture.store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    run_variant_lift_pattern(
        json!({"fingerprint":fixture.finding().fingerprint}),
        &ctx,
        None,
    )
}

#[test]
fn an_unreviewed_finding_never_reaches_the_model_requirement() {
    let fixture = ReviewedFindingFixture::new();
    let result = lift(&fixture).unwrap();
    assert_eq!(result["data"]["reason"], "missing-triage");
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("no confirming review decision"));
}

#[test]
fn current_human_rejection_overrides_automated_confirmation() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_auto_triage(TriageVerdict::TruePositive);
    fixture.record_human_decision(ReviewDecisionVerdict::RejectedFalsePositive);
    let result = lift(&fixture).unwrap();
    assert_eq!(result["data"]["reason"], "non-true-positive");
    assert_eq!(result["data"]["reviewAuthor"], "human");
}

#[test]
fn human_confirmation_is_named_as_human_in_the_draft_prompt() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_human_decision(ReviewDecisionVerdict::Confirmed);
    let finding = fixture.finding();
    let confirmation = variant_confirmation(
        "variant:lift-pattern",
        &finding.fingerprint,
        crate::findings::load_finding_review_gate(&fixture.store, &finding).unwrap(),
    )
    .unwrap();
    let prompt = build_variant_lift_prompt(&finding, &confirmation);
    assert!(prompt.contains("Review decision:\nVerdict: confirmed\nAuthor: human"));
    assert!(!prompt.contains("Triage assessment:"));
    assert!(lift(&fixture).unwrap_err().to_string().contains("runtime"));
}

#[test]
fn response_is_an_unaccepted_draft_with_no_context_activation() {
    let fixture = ReviewedFindingFixture::new();
    let response = variant_lift_response(
        "owned".into(),
        json!({"owned":true}),
        fixture.finding(),
        "Labeled owned draft".into(),
        crate::runtime::RuntimeCostReport::UNAVAILABLE,
    );
    assert_eq!(response["data"]["draft"], true);
    assert_eq!(response["data"]["accepted"], false);
    assert_eq!(response["data"]["contextActivated"], false);
    assert_eq!(response["summary"], "Unaccepted source-pattern draft");
}

#[test]
fn absent_reasoning_override_inherits_runtime_and_explicit_effort_is_preserved() {
    let fixture = ReviewedFindingFixture::new();
    let inherited = variant_lift_request(
        "openai:gpt-4.1".into(),
        &fixture.workspace,
        "Owned source-pattern input".into(),
        None,
    )
    .unwrap();
    assert_eq!(inherited.thinking_level, None);
    let selected = variant_lift_request(
        "openai:gpt-4.1".into(),
        &fixture.workspace,
        "Owned source-pattern input".into(),
        Some("low"),
    )
    .unwrap();
    assert_eq!(selected.thinking_level.as_deref(), Some("low"));
}
