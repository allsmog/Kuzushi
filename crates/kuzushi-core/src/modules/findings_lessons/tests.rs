use super::*;

#[test]
fn lesson_options_are_shared_and_do_not_complete_review() {
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
    for tool in lesson_tools() {
        assert!(!registry.resolve_tool(&tool.name).unwrap().phase_result);
        assert_eq!(tool.runtime_requirement, RuntimeRequirement::Never);
    }
    let input = registry
        .prepare_dispatch_input("findings:lessons", json!({}), &ctx, None)
        .unwrap();
    let result = registry
        .dispatch_prepared_input_with_runtime(input, &ctx, None)
        .unwrap();
    assert_eq!(result["data"]["rows"], json!([]));
    let prepared=registry.prepare_dispatch_input("findings:lesson-save",json!({"findingId":1,"content":{"title":"Owned note","text":"Review recorded source","applicability":"Source review","limitations":"Historical guidance"}}),&ctx,None).unwrap();
    let error = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("explicit operator authorization"));
    assert!(store.finding_lessons(50, 0).unwrap().rows.is_empty());
    assert!(registry
        .prepare_dispatch_input(
            "findings:lesson-review",
            json!({"unknown":true}),
            &ctx,
            None
        )
        .is_err());
    assert!(registry
        .prepare_dispatch_input("findings:lessons", json!({"limit":201}), &ctx, None)
        .is_err());
}
