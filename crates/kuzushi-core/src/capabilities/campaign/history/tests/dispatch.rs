use super::*;
use crate::modules::{ModuleRegistry, ToolExecutionContext};

#[test]
fn prepared_status_retains_readable_history_and_reports_a_partial_result() {
    let root = tempfile::tempdir().unwrap();
    write_plan(root.path(), "readable", json!([]));
    let broken = write_plan(root.path(), "broken", json!([]));
    fs::write(broken.join("plan.json"), "{").unwrap();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let store = crate::FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input("campaign:status", json!({}), &ctx, None)
        .unwrap();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["campaigns"].as_array().unwrap().len(), 1);
    assert_eq!(result["data"]["historyCoverage"]["complete"], false);
    assert_eq!(result["data"]["trend"]["providerSpendUnresolved"], true);
    assert!(!super::super::super::campaign_queue_path(root.path(), "readable").exists());
}

#[test]
fn canceled_prepared_status_writes_no_trend_or_work() {
    let root = tempfile::tempdir().unwrap();
    write_plan(root.path(), "readable", json!([]));
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let store = crate::FindingStore::open(workspace.findings_db_path()).unwrap();
    let cancellation = crate::ScanCancellation::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: Some(&cancellation),
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input("campaign:status", json!({}), &ctx, None)
        .unwrap();
    cancellation.cancel();
    let result = registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None);
    assert!(result.is_err());
    assert!(!super::super::super::trend_history::trend_history_path(root.path()).exists());
    assert!(!super::super::super::campaign_queue_path(root.path(), "readable").exists());
}
