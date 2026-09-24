use super::*;
use crate::findings::{TriageOutcome, TriageVerdict};
use std::collections::VecDeque;
use std::sync::Mutex;

struct ScriptedPatchRuntime {
    responses: Mutex<VecDeque<anyhow::Result<crate::runtime::AgentQueryResponse>>>,
}

impl ScriptedPatchRuntime {
    fn new(responses: Vec<anyhow::Result<crate::runtime::AgentQueryResponse>>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
        }
    }
}

impl AgentRuntime for ScriptedPatchRuntime {
    fn query_blocking(
        &self,
        _request: AgentQueryRequest,
    ) -> Result<crate::runtime::AgentQueryResponse> {
        self.responses.lock().unwrap().pop_front().unwrap()
    }

    fn triage_finding_blocking(
        &self,
        _request: crate::runtime::TriageRequest,
    ) -> Result<TriageOutcome> {
        unreachable!("patch synthesis tests do not triage")
    }
}

#[test]
fn structured_repair_cost_is_counted_once() {
    let runtime = ScriptedPatchRuntime::new(vec![
        Ok(response("not json", None, 0.1, true)),
        Ok(response("", Some(valid_patch()), 0.2, true)),
    ]);

    let synthesis = synthesize_for_test(&runtime).unwrap();

    let cost = synthesis.cost.exact_usd().unwrap();
    assert!((cost - 0.3).abs() < 1e-9);
}

#[test]
fn successful_unpriced_synthesis_preserves_unresolved_state() {
    let runtime =
        ScriptedPatchRuntime::new(vec![Ok(response("", Some(valid_patch()), 0.0, false))]);

    let synthesis = synthesize_for_test(&runtime).unwrap();

    assert_eq!(synthesis.cost.observed_usd(), 0.0);
    assert!(!synthesis.cost.is_complete());
}

#[test]
fn invalid_provider_cost_fails_before_patch_synthesis_succeeds() {
    for invalid in [-1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let runtime =
            ScriptedPatchRuntime::new(vec![Ok(response("", Some(valid_patch()), invalid, true))]);

        assert!(synthesize_for_test(&runtime).is_err());
    }
}

#[test]
fn multiple_patch_attempts_accumulate_observed_cost_and_incomplete_state() {
    let first = RuntimeCostReport::known(RuntimeCost::from_usd(0.1, "first").unwrap());
    let second = RuntimeCostReport::incomplete(RuntimeCost::from_usd(0.2, "second").unwrap());

    let total = super::run_patch_finding::accumulate_patch_cost(first, second).unwrap();

    assert!((total.observed_usd() - 0.3).abs() < 1e-9);
    assert!(!total.is_complete());
}

#[test]
fn multiple_exact_patch_attempts_preserve_the_exact_sum() {
    let first = RuntimeCostReport::known(RuntimeCost::from_usd(0.123_456_7, "first").unwrap());
    let second = RuntimeCostReport::known(RuntimeCost::from_usd(0.2, "second").unwrap());

    let total = super::run_patch_finding::accumulate_patch_cost(first, second).unwrap();

    assert!((total.exact_usd().unwrap() - 0.323_456_7).abs() < 1e-12);
}

#[test]
fn exact_patch_output_terminalizes_run_with_the_same_cost_once() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "patch-cost-run";
    let record =
        crate::run_artifacts::ToolRunRecord::new(target.path(), run_id, "tool", "patch:finding");
    crate::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        &json!({}),
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    let result = patch_result_with_cost(0.3, false);
    let output = patch_result_to_tool_json("fp", &result, "ok", None).unwrap();

    crate::run_artifacts::try_record_tool_run_complete(record, &output).unwrap();

    let summary = crate::run_artifacts::load_run_summary(target.path(), run_id).unwrap();
    assert_eq!(summary.cost_usd, Some(0.3));
}

fn synthesize_for_test(runtime: &ScriptedPatchRuntime) -> Result<PatchSynthesis> {
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("demo.rs"), "fn vulnerable() {}\n").unwrap();
    let finding = Finding::new_tool(
        "test",
        "test/rule",
        "demo.rs",
        1,
        Some(1),
        crate::findings::Severity::High,
        "vulnerable",
    );
    let triage = TriageOutcome { first_link: None, refute_reason: None,
        verdict: TriageVerdict::TruePositive,
        confidence: 1.0,
        rationale: "confirmed".to_string(),
        cost_usd: 0.0,
        cost_usd_exact: true,
    };
    synthesize_patch(
        runtime,
        "test:model",
        target.path(),
        "repo",
        &finding,
        &ReviewConfirmation::AutomatedTriage(triage),
        &[],
        PatchStyle::Minimal,
        "system",
    )
}

fn response(
    text: &str,
    structured: Option<Value>,
    cost_usd: f64,
    cost_usd_reported: bool,
) -> crate::runtime::AgentQueryResponse {
    crate::runtime::AgentQueryResponse {
        text: text.to_string(),
        structured,
        cost_usd,
        cost_usd_reported,
        ..crate::runtime::AgentQueryResponse::default()
    }
}

fn valid_patch() -> Value {
    json!({
        "diff": "diff --git a/demo.rs b/demo.rs\n",
        "explanation": "fix"
    })
}

fn patch_result_with_cost(cost_usd: f64, provider_spend_unresolved: bool) -> PatchResult {
    PatchResult {
        patch_run_id: "patch-cost".to_string(),
        fingerprint: "fp".to_string(),
        repo: "/repo".to_string(),
        diff: None,
        status: PatchStatus::Sound,
        iterations: 2,
        build_command: None,
        test_command: None,
        worktree_path: None,
        cost_usd: Some(cost_usd),
        provider_spend_unresolved,
        validator_log: None,
        history: Vec::new(),
        provenance: None,
        created_at: None,
        updated_at: None,
    }
}
