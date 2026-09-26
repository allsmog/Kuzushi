use crate::config::V2Config;
use crate::findings::test_support::ReviewedFindingFixture;
use crate::findings::{ReviewDecisionVerdict, TriageVerdict};
use crate::modules::{ModuleRegistry, ToolExecutionContext};
use serde_json::{json, Value};

/// Dispatch `verify:finding` without a runtime: a finding the review gate
/// admits reaches the runtime requirement, one it refuses returns a refusal.
fn verify_without_runtime(fixture: &ReviewedFindingFixture) -> anyhow::Result<Value> {
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&fixture.workspace),
        findings_store: Some(&fixture.store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    ModuleRegistry::with_v2_builtins().execute_tool(
        "verify:finding",
        json!({"fingerprint": fixture.finding().fingerprint}),
        &ctx,
    )
}

fn refusal_output(result: &Value) -> &str {
    assert_eq!(result["ok"], json!(false), "{result}");
    result["output"].as_str().unwrap()
}

#[test]
fn human_confirmed_finding_without_triage_passes_the_review_gate() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_human_decision(ReviewDecisionVerdict::Confirmed);

    let error = verify_without_runtime(&fixture).unwrap_err().to_string();

    assert!(error.contains("requires the LangGraph runtime"), "{error}");
}

#[test]
fn unreviewed_finding_names_triage_and_review_decision_remedies() {
    let fixture = ReviewedFindingFixture::new();

    let result = verify_without_runtime(&fixture).unwrap();

    assert_eq!(result["data"]["reason"], json!("missing-triage"));
    let output = refusal_output(&result);
    assert!(output.contains("no triage verdict and no confirming review decision"));
    assert!(output.contains("Run triage:run first, or record a confirmed or to_fix review decision."));
}

#[test]
fn human_rejection_refuses_verification_even_over_automated_true_positive() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_auto_triage(TriageVerdict::TruePositive);
    fixture.record_human_decision(ReviewDecisionVerdict::RejectedFalsePositive);

    let result = verify_without_runtime(&fixture).unwrap();

    assert_eq!(result["data"]["reason"], json!("reviewer-dismissed"));
    assert_eq!(result["data"]["reviewAuthor"], json!("human"));
    assert!(refusal_output(&result).contains(
        "dismissed by a human review decision (rejected_false_positive); verification is not needed"
    ));
}

#[test]
fn automated_false_positive_remains_verifiable() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_auto_triage(TriageVerdict::FalsePositive);

    let error = verify_without_runtime(&fixture).unwrap_err().to_string();

    assert!(error.contains("requires the LangGraph runtime"), "{error}");
}
