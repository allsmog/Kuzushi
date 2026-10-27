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

#[test]
fn direct_iac_child_source_detects_parent_drift_before_settlement() {
    let root = tempfile::tempdir().unwrap();
    let child = root.path().join("child");
    std::fs::create_dir(&child).unwrap();
    let raw = "FROM owned:latest\nUSER nobody\n";
    std::fs::write(child.join("Dockerfile"), raw).unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let child = workspace.root().join("child");
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
    let output = run_with_scanner(json!({"target":child}), &ctx, |target, options, cancel| {
        let report = scan_iac(target, options, cancel)?;
        std::fs::write(
            root.path().join("README.md"),
            "Owned parent edit, never executed.\n",
        )?;
        Ok(report)
    })
    .unwrap();
    assert_eq!(output["status"], "partial");
    assert_eq!(output["data"]["sourceCheckCurrent"], false);
    let run = output["data"]["persisted"]["runId"].as_str().unwrap();
    assert_eq!(store.run_status(run).unwrap().as_deref(), Some("partial"));
    let findings = store.list_all_findings().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].file_path, "child/Dockerfile");
    assert!(!child.join(".kuzushi").exists());
}
