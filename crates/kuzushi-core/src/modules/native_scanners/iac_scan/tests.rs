use super::*;
use crate::{FindingStore, V2Config, WorkspaceTarget};

#[test]
fn direct_iac_source_drift_preserves_partial_observations() {
    assert_source_settlement(true);
}

#[test]
fn direct_iac_empty_source_drift_cannot_complete_the_ledger_run() {
    assert_source_settlement(false);
}

fn assert_source_settlement(positive: bool) {
    let root = tempfile::tempdir().unwrap();
    if positive {
        std::fs::write(
            root.path().join("Dockerfile"),
            "FROM owned:latest\nUSER root\n",
        )
        .unwrap();
    }
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
    let output = run_with_scanner(json!({}), &ctx, |target, options, cancellation| {
        let report = scan_iac(target, options, cancellation)?;
        std::fs::write(target.join("README.md"), "Planned inert operator edit.\n")?;
        Ok(report)
    })
    .unwrap();
    assert_eq!(output["status"], "partial");
    let run = output["data"]["persisted"]["runId"].as_str().unwrap();
    assert_eq!(store.run_status(run).unwrap().as_deref(), Some("partial"));
    assert_eq!(store.list_all_findings().unwrap().is_empty(), !positive);
    assert_eq!(output["data"]["sourceCheckCurrent"], false);
}
