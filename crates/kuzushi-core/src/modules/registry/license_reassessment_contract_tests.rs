use crate::findings::{
    compare_scan_runs, ReviewDecision, ReviewDecisionVerdict, ScanObservationPresence, TriageAuthor,
};
use crate::run_artifacts::{
    record_tool_run_started, try_record_tool_run_complete_settled, ToolRunRecord, TraceHandle,
};
use crate::{FindingStore, ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::fs;

fn dispatch(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run: &str,
    tool: &str,
    input: Value,
) -> Value {
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let trace = (tool != "sast:scan").then(|| TraceHandle::jsonl(workspace.root(), run));
    let record = ToolRunRecord::new(workspace.root(), run, "tool", tool);
    if tool != "sast:scan" {
        record_tool_run_started(record, &input);
    }
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: trace.as_ref(),
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input(tool, input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let output = settled_dispatch(&registry, prepared, &ctx, record);
    assert_eq!(output["status"], "completed", "{output:#}");
    output
}

fn settled_dispatch(
    registry: &ModuleRegistry,
    prepared: crate::modules::PreparedToolInput,
    ctx: &ToolExecutionContext<'_>,
    record: ToolRunRecord<'_>,
) -> Value {
    let Some(observation) = ctx.run_observation() else {
        return registry
            .dispatch_prepared_input_with_runtime(prepared, ctx, None)
            .unwrap();
    };
    let dispatched = registry
        .dispatch_prepared_input_observed_with_runtime(prepared, ctx, None)
        .unwrap();
    let output = dispatched.execution.unwrap();
    try_record_tool_run_complete_settled(record, &output, &observation, dispatched.completion)
        .unwrap();
    assert_observation_artifact(record, &output);
    output
}

fn assert_observation_artifact(record: ToolRunRecord<'_>, output: &Value) {
    let (_, body) =
        crate::run_artifacts::read_run_artifact_text(record.target, record.run_id, "findings.json")
            .require("Direct discovery observation snapshot")
            .unwrap();
    let findings: Vec<crate::Finding> = serde_json::from_str(&body).unwrap();
    assert_eq!(
        findings.len() as u64,
        output["data"]["count"].as_u64().unwrap()
    );
    let scan = crate::run_artifacts::load_scan_stage_data(record.target, record.run_id)
        .unwrap()
        .unwrap()
        .scan
        .unwrap();
    let artifact = crate::run_artifacts::load_run_artifacts(record.target, record.run_id)
        .unwrap()
        .into_iter()
        .find(|artifact| artifact.path == "findings.json")
        .expect("The direct scan publishes its observation snapshot");
    assert!(
        scan.artifact_delta
            .iter()
            .any(|delta| { delta.run_ref == record.run_id && delta.path == artifact.path }),
        "Saved observations must appear in the Scan artifact delta"
    );
}

fn owned_fixture(
    licensed: bool,
    source: bool,
) -> (tempfile::TempDir, WorkspaceTarget, FindingStore) {
    let root = tempfile::tempdir().unwrap();
    package(root.path(), licensed);
    if source {
        fs::create_dir(root.path().join("src")).unwrap();
        fs::write(
            root.path().join("src/lib.rs"),
            "// Owned inert source. Never executed.\n",
        )
        .unwrap();
    }
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    (root, workspace, store)
}

fn confirm_policy_fixture(store: &FindingStore, finding: &crate::Finding) {
    store
        .append_user_review_decision(
            finding.id.unwrap(),
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Confirmed,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "Scripted review of owned policy metadata".into(),
                dismiss_reason: None,
                actor: Some("fixture-operator".into()),
            },
        )
        .unwrap();
}

fn package(root: &std::path::Path, licensed: bool) {
    let value = if licensed {
        json!({"name":"owned-license-fixture", "license":"MIT"})
    } else {
        json!({"name":"owned-license-fixture"})
    };
    fs::write(
        root.join("package.json"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    fs::write(root.join("LICENSE"), "MIT License\n").unwrap();
}

fn sast_input(run: &str) -> Value {
    json!({"runId":run,"taskMode":"manual","tasks":["license-scan"],
        "triage":false,"verify":false,"autoPatch":false})
}

#[test]
fn disabling_header_policy_is_not_reassessment_of_the_old_header_finding() {
    let (_root, workspace, store) = owned_fixture(true, true);
    let base = dispatch(
        &workspace,
        &store,
        "header-policy-base",
        "license-scan:scan",
        json!({"requireSourceSpdxHeaders":true}),
    );
    let finding = store.list_all_findings().unwrap().remove(0);
    assert_eq!(finding.rule_id, "license-scan/missing-spdx-header");
    let output = dispatch(
        &workspace,
        &store,
        "header-policy-disabled",
        "sast:scan",
        sast_input("header-policy-disabled"),
    );
    assert_eq!(output["data"]["findingsCount"], 0);
    assert_eq!(base["data"]["treeHash"], output["data"]["treeHash"]);
    let stored = store.list_all_findings().unwrap().remove(0);
    assert!(
        stored.observation_gap.is_none(),
        "Disabled policy did not re-examine this signal: {stored:#?}"
    );
    let comparison =
        compare_scan_runs(&store, "header-policy-base", "header-policy-disabled").unwrap();
    assert_eq!(comparison.findings.len(), 1);
    assert_eq!(
        comparison.findings[0].observation_presence(),
        ScanObservationPresence::NotReassessed
    );
}

#[test]
fn completed_empty_direct_scan_records_a_gap_without_overriding_human_review() {
    let (root, workspace, store) = owned_fixture(false, false);
    dispatch(
        &workspace,
        &store,
        "license-direct-base",
        "license-scan:scan",
        json!({}),
    );
    let finding = store.list_all_findings().unwrap().remove(0);
    assert_eq!(finding.rule_id, "license-scan/missing-license");
    confirm_policy_fixture(&store, &finding);
    package(root.path(), true);
    let output = dispatch(
        &workspace,
        &store,
        "license-direct-empty",
        "license-scan:scan",
        json!({}),
    );
    assert_eq!(output["data"]["count"], 0);
    let stored = store.list_all_findings().unwrap().remove(0);
    let gap = stored
        .observation_gap
        .expect("A completed direct policy scan must retain covered absence");
    assert_eq!(gap.last_seen_run_id.as_deref(), Some("license-direct-base"));
    assert_eq!(gap.compared_run_id.as_deref(), Some("license-direct-empty"));
    assert_eq!(store.list_all_review_decisions().unwrap().len(), 1);
    crate::run_artifacts::load_scan_stage_data(workspace.root(), "license-direct-empty")
        .expect("Direct coverage must remain authenticated after result settlement")
        .expect("Direct coverage must survive restart readers");
    let comparison =
        compare_scan_runs(&store, "license-direct-base", "license-direct-empty").unwrap();
    assert_eq!(
        comparison.findings[0].observation_presence(),
        ScanObservationPresence::NotObserved,
        "{comparison:#?}"
    );
}
