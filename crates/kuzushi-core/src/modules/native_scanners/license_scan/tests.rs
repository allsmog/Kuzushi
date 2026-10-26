use super::*;
use crate::module_result::ToolResultStatus;
use crate::run_artifacts::TraceHandle;
use crate::{FindingStore, V2Config, WorkspaceTarget};
use std::fs;

#[test]
fn source_change_before_persistence_keeps_the_run_partial_and_preserves_earlier_signals() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"name":"owned-policy"}"#,
    )
    .unwrap();
    fs::write(root.path().join("LICENSE"), "MIT License\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = V2Config::default();
    let base_trace = TraceHandle::jsonl(workspace.root(), "before-source-change");
    let mut ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: Some(&base_trace),
        cancellation: None,
        authorization: Default::default(),
    };
    run(json!({}), &ctx).unwrap();
    let trace = TraceHandle::jsonl(workspace.root(), "changed-source");
    ctx.trace = Some(&trace);
    fs::write(
        root.path().join("package.json"),
        r#"{"name":"owned-policy","license":"MIT"}"#,
    )
    .unwrap();
    let snapshot = SourceSnapshot::capture(&ctx, TOOL, workspace.root()).unwrap();
    let target_snapshot = PhaseTargetSnapshot::capture(workspace.root());
    let started = Instant::now();
    let (output, findings) = scan(workspace.root(), LicenseScanOptions::default(), &ctx).unwrap();
    assert!(findings.is_empty());
    fs::write(root.path().join("unexecuted.txt"), "Owned source drift\n").unwrap();
    let output = snapshot.finish(&ctx, TOOL, workspace.root(), output);
    let receipt = receipt::LicenseScanReceipt {
        options: LicenseScanOptions::default(),
        started,
        target_snapshot,
    };
    let output = finish(&ctx, &findings, output, receipt).unwrap();
    assert_eq!(output["status"], "partial");
    assert_eq!(
        store.run_status("changed-source").unwrap().as_deref(),
        Some("partial")
    );
    assert_eq!(output["data"]["phaseStages"][0]["outcome"], "partial");
    assert!(store.list_all_findings().unwrap()[0]
        .observation_gap
        .is_none());
}

#[test]
fn failed_or_skipped_policy_results_have_no_completed_persistence_status() {
    assert_eq!(scan_persistence_status(ToolResultStatus::Failed), None);
    assert_eq!(scan_persistence_status(ToolResultStatus::Skipped), None);
}

#[test]
fn observation_publication_failure_retains_the_captured_source_identity() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"name":"owned-policy","license":"MIT"}"#,
    )
    .unwrap();
    fs::write(root.path().join("LICENSE"), "MIT License\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = V2Config::default();
    let trace = TraceHandle::jsonl(workspace.root(), "publication-failure");
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: Some(&trace),
        cancellation: None,
        authorization: Default::default(),
    };
    let collision = crate::run_artifacts::run_dir(workspace.root(), "publication-failure")
        .join("findings.json");
    fs::create_dir_all(collision).unwrap();
    let before = crate::incremental_index::current_workspace_tree_hash(workspace.root()).unwrap();
    let error = run(json!({}), &ctx).unwrap_err();
    let snapshot = crate::workspace::source_snapshot::failed_source_snapshot(&error)
        .expect("IO failure must not discard the pre-execution source identity");
    assert_eq!(
        snapshot.attach(json!({"data":{}}))["data"]["treeHash"],
        before
    );
    assert!(error.to_string().contains("findings.json"), "{error:#}");
}

#[test]
fn oversized_license_result_keeps_the_read_limit_cause_for_operator_recovery() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"name":"owned-policy","license":"MIT"}"#,
    )
    .unwrap();
    fs::File::create(root.path().join("LICENSE"))
        .unwrap()
        .set_len(2 * 1024 * 1024 + 1)
        .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let output = run(json!({}), &ctx).unwrap();
    assert_eq!(output["status"], "failed");
    assert!(
        output["output"].as_str().unwrap().contains("2097152"),
        "{output:#}"
    );
    assert!(output["errors"][0].as_str().unwrap().contains("2097152"));
    assert!(store.list_all_findings().unwrap().is_empty());
    assert!(output["data"].get("coreFindings").is_none());
}
