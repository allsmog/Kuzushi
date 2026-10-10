use super::*;

#[test]
fn group_options_prepare_and_reject_unknown_inputs_without_requiring_a_model() {
    let root = tempfile::tempdir().unwrap();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = crate::V2Config::default();
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
        .prepare_dispatch_input("findings:groups", json!({}), &ctx, None)
        .unwrap();
    let value = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(value["data"]["totalGroups"], 0);
    assert!(registry
        .prepare_dispatch_input("findings:groups", json!({"unknown":true}), &ctx, None)
        .is_err());
    let invalid = registry
        .prepare_dispatch_input("findings:groups", json!({"offset":-1}), &ctx, None)
        .unwrap();
    assert!(registry
        .dispatch_prepared_input_with_runtime(invalid, &ctx, None)
        .is_err());
}
