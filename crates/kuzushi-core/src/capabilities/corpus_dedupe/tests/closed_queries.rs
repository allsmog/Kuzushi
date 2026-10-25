use super::*;
use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, TriageRequest};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct InvalidRuntime {
    calls: AtomicUsize,
}

impl AgentRuntime for InvalidRuntime {
    fn query_blocking(&self, _: AgentQueryRequest) -> anyhow::Result<AgentQueryResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(AgentQueryResponse {
            text: "invalid structured response".into(),
            cost_usd: 0.2,
            cost_usd_reported: true,
            ..Default::default()
        })
    }
    fn triage_finding_blocking(
        &self,
        _: TriageRequest,
    ) -> anyhow::Result<crate::findings::TriageOutcome> {
        panic!("duplicate proposals do not invoke triage")
    }
}

fn assert_closed_failure(error: anyhow::Error, runtime: &InvalidRuntime) {
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 1);
    assert!(error.to_string().contains("no model repair request"));
    let cost = error
        .downcast_ref::<crate::structured_output::StructuredOutputError>()
        .unwrap()
        .cost_report();
    assert_eq!(cost.observed_usd(), 0.2);
    assert!(cost.is_complete());
}

#[test]
fn malformed_judge_output_retains_paid_usage_without_a_repair_query() {
    let (root, store) = seeded_store();
    let findings = dedupe_candidates(&store, 200).unwrap();
    let index = fingerprint_index(&findings);
    let runtime = InvalidRuntime::default();
    let request = super::super::dedupe_prompt::dedupe_request(
        "openai-codex:gpt-5.5",
        root.path(),
        &findings,
        131072,
    )
    .unwrap();
    let error = super::super::dedupe_prompt::query_dedupe(&runtime, request, 16, &index)
        .err()
        .unwrap();
    assert_closed_failure(error, &runtime);
    assert_eq!(store.list_all_findings().unwrap().len(), 2);
}

#[test]
fn malformed_confirmation_retains_paid_usage_without_a_repair_query() {
    let (root, store) = seeded_store();
    let source_root = root.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.path().join("webapp")).unwrap();
    std::fs::write(
        root.path().join("webapp/files.py"),
        "owned source\n".repeat(30),
    )
    .unwrap();
    let findings = dedupe_candidates(&store, 200).unwrap();
    let index = fingerprint_index(&findings);
    let mut groups = one_group(&findings);
    groups[0].confidence = 0.5;
    let judged = super::super::JudgedGroups {
        groups,
        dropped: Default::default(),
    };
    let options = super::super::DedupeOptions::from_input(&serde_json::json!({})).unwrap();
    let runtime = InvalidRuntime::default();
    let mut cost = crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO);
    let error = super::super::escalate::escalate_low_confidence(
        &runtime,
        "openai-codex:gpt-5.5",
        &source_root,
        judged,
        &index,
        &options,
        &mut cost,
    )
    .err()
    .unwrap();
    assert_closed_failure(error, &runtime);
    assert_eq!(store.list_all_findings().unwrap().len(), 2);
}
