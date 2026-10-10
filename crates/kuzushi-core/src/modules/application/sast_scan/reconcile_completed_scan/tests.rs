use super::*;
use crate::findings::{ReviewDecision, ReviewDecisionVerdict, TriageAuthor};
use crate::modules::{ModuleRegistry, ToolExecutionContext};
use crate::{V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::fs;

fn dispatch(workspace: &WorkspaceTarget, store: &FindingStore, run: &str, paths: Value) -> Value {
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input(
            "sast:scan",
            json!({
                "runId":run, "taskMode":"manual", "tasks":["secret-scan"], "paths":paths,
                "triage":false,"verify":false,"autoPatch":false,
            }),
            &ctx,
            None,
        )
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap()
}

fn write_example(path: &std::path::Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, "# AWS documentation example, not a real credential.\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n").unwrap();
}

#[test]
fn empty_completed_native_scan_records_a_gap_and_preserves_the_human_verdict() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("config.env");
    write_example(&path);
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    dispatch(&workspace, &store, "base", json!([]));
    let finding = store.list_all_findings().unwrap().remove(0);
    store
        .append_user_review_decision(
            finding.id.unwrap(),
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Confirmed,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "Owned documentation example reviewed".into(),
                dismiss_reason: None,
                actor: Some("operator".into()),
            },
        )
        .unwrap();
    fs::write(&path, "# Documentation example removed; no fix claim.\n").unwrap();
    let output = dispatch(&workspace, &store, "empty", json!([]));
    assert_eq!(output["status"], "completed");
    assert_eq!(output["data"]["coreFindings"], json!([]));
    let rows = store.list_all_findings().unwrap();
    assert_eq!(rows.len(), 1);
    let gap = rows[0].observation_gap.as_ref().unwrap();
    assert_eq!(gap.last_seen_run_id.as_deref(), Some("base"));
    assert_eq!(gap.compared_run_id.as_deref(), Some("empty"));
    assert_eq!(store.list_all_review_decisions().unwrap().len(), 1);
    assert!(store
        .reconcile_disappeared_findings("empty")
        .unwrap()
        .disappeared
        .is_empty());
}

#[test]
fn completed_empty_scoped_scan_does_not_record_gaps_outside_its_receipt() {
    let root = tempfile::tempdir().unwrap();
    for name in ["service/config.env", "other/config.env"] {
        write_example(&root.path().join(name));
    }
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    dispatch(&workspace, &store, "base", json!([]));
    for name in ["service/config.env", "other/config.env"] {
        fs::write(root.path().join(name), "# Owned empty fixture.\n").unwrap();
    }
    dispatch(&workspace, &store, "scoped-empty", json!(["service"]));
    let rows = store.list_all_findings().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows
        .iter()
        .find(|row| row.file_path == "service/config.env")
        .unwrap()
        .observation_gap
        .is_some());
    assert!(rows
        .iter()
        .find(|row| row.file_path == "other/config.env")
        .unwrap()
        .observation_gap
        .is_none());
}

#[test]
fn noncompleted_receipts_or_ledger_runs_cannot_enable_gap_reconciliation() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    write_example(&root.path().join("config.env"));
    dispatch(&workspace, &store, "base", json!([]));
    let scan = crate::run_artifacts::load_scan_stage_data(workspace.root(), "base")
        .unwrap()
        .unwrap()
        .scan
        .unwrap();
    for status in ["running", "partial", "failed", "canceled"] {
        store
            .record_run_started(status, root.path(), status)
            .unwrap();
        after_receipt(&store, status, PhaseStageOutcome::Completed, &scan).unwrap();
    }
    after_receipt(&store, "base", PhaseStageOutcome::Partial, &scan).unwrap();
    store
        .record_run_started("foreign", workspace.root(), "completed")
        .unwrap();
    let mut foreign = scan.clone();
    foreign.scope.target = "/owned-other-target".into();
    after_receipt(&store, "foreign", PhaseStageOutcome::Completed, &foreign).unwrap();
    assert!(store.list_all_findings().unwrap()[0]
        .observation_gap
        .is_none());
}

#[test]
fn positive_control_in_a_scoped_scan_does_not_mark_an_unscanned_finding_absent() {
    let root = tempfile::tempdir().unwrap();
    for name in ["service/config.env", "other/config.env"] {
        write_example(&root.path().join(name));
    }
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    dispatch(&workspace, &store, "base", json!([]));
    for name in ["service/config.env", "other/config.env"] {
        fs::write(root.path().join(name), "# Owned empty fixture.\n").unwrap();
    }
    write_example(&root.path().join("service/control.env"));
    dispatch(&workspace, &store, "scoped-control", json!(["service"]));
    let rows = store.list_all_findings().unwrap();
    assert_eq!(rows.len(), 3);
    assert!(rows
        .iter()
        .find(|row| row.file_path == "service/config.env")
        .unwrap()
        .observation_gap
        .is_some());
    assert!(rows
        .iter()
        .find(|row| row.file_path == "other/config.env")
        .unwrap()
        .observation_gap
        .is_none());
    assert!(rows
        .iter()
        .find(|row| row.file_path == "service/control.env")
        .unwrap()
        .observation_gap
        .is_none());
}
