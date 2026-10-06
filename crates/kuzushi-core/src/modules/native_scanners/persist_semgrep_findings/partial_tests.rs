use super::*;
use crate::modules::{ModuleRegistry, ToolExecutionContext};
use crate::run_artifacts::TraceHandle;
use crate::{FindingStore, V2Config, WorkspaceTarget};
use std::os::unix::fs::PermissionsExt;

#[test]
fn standalone_semgrep_retains_partial_status_and_observations_after_reopen() {
    let root = tempfile::tempdir().unwrap();
    let binary = protocol_fixture(root.path(), true);
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let output = dispatch(&workspace, &store, &binary, "standalone-partial");

    assert_eq!(
        crate::tool_result_status(&output),
        crate::ToolResultStatus::Partial
    );
    assert_eq!(
        output["data"]["scanErrors"][0],
        "omitted.rs: labeled protocol gap"
    );
    assert_eq!(output["data"]["snapshotHash"].as_str().unwrap().len(), 64);
    assert_eq!(output["data"]["treeHash"].as_str().unwrap().len(), 64);
    assert_partial_run(&store, "standalone-partial", 1);
    assert_committed_delta(root.path(), "standalone-partial", 1);
    drop(store);
    let reopened = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert_partial_run(&reopened, "standalone-partial", 1);
}

#[test]
fn standalone_semgrep_zero_findings_with_a_gap_cannot_be_completed() {
    let root = tempfile::tempdir().unwrap();
    let binary = protocol_fixture(root.path(), false);
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let output = dispatch(&workspace, &store, &binary, "standalone-empty-partial");

    assert_eq!(
        crate::tool_result_status(&output),
        crate::ToolResultStatus::Partial
    );
    assert_partial_run(&store, "standalone-empty-partial", 0);
    assert_committed_delta(root.path(), "standalone-empty-partial", 0);
}

fn assert_partial_run(store: &FindingStore, run_id: &str, expected_count: usize) {
    assert_eq!(
        store.run_status(run_id).unwrap().as_deref(),
        Some("partial")
    );
    assert_eq!(
        store.list_findings_for_scan_id(run_id).unwrap().len(),
        expected_count
    );
}

fn assert_committed_delta(root: &Path, run_id: &str, expected_added: u64) {
    let projection = crate::run_lifecycle::load_run_projection(root, run_id)
        .unwrap()
        .projection;
    let delta = projection
        .finding_deltas
        .last()
        .expect("partial finding commits emit a measured delta");
    assert_eq!(
        (delta.added, delta.updated, delta.removed),
        (expected_added, 0, 0)
    );
}

fn dispatch(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    binary: &Path,
    run_id: &str,
) -> Value {
    let registry = ModuleRegistry::with_v2_builtins();
    let config = V2Config::default();
    let trace = TraceHandle::jsonl(workspace.root(), run_id);
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: Some(&trace),
        cancellation: None,
        authorization: Default::default(),
    };
    let input = json!({"binary": binary, "config": "labeled-protocol-fixture"});
    let prepared = registry
        .prepare_dispatch_input("semgrep:scan", input, &ctx, None)
        .unwrap();
    registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap()
}

fn protocol_fixture(root: &Path, include_finding: bool) -> PathBuf {
    std::fs::write(root.join("app.rs"), "fn main() {}\n").unwrap();
    let results = if include_finding {
        json!([{"check_id":"labeled-protocol-fixture", "path":"app.rs",
        "start":{"line":1}, "extra":{"severity":"WARNING", "message":"Labeled protocol observation"}}])
    } else {
        json!([])
    };
    let report = json!({"results":results,"errors":[{"path":"omitted.rs","message":"labeled protocol gap"}]});
    let binary = root.join("semgrep-protocol-fixture.sh");
    std::fs::write(&binary, format!("#!/bin/sh\nprintf '%s' '{report}'\n")).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    binary
}
