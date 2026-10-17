use super::*;

fn dispatch(
    root: &std::path::Path,
    input: Value,
    cancellation: Option<&crate::scan::ScanCancellation>,
) -> Result<Value> {
    let workspace = crate::WorkspaceTarget::new(root)?;
    let config = crate::V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation,
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input("worklist:rank", input, &ctx, None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}

#[test]
fn deep_prepared_dispatch_preserves_inspection_and_partial_state_without_runtime() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("owned.c");
    let text = "// Owned parser packet length metadata. Never executed.\n".repeat(2000);
    std::fs::write(&path, &text).unwrap();
    let result = dispatch(root.path(), json!({"deep":true,"limit":500}), None).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["systemsInspection"]["status"], "partial");
    assert_eq!(result["data"]["systemsInspection"]["maxSourceFiles"], 2000);
    assert!(!result["warnings"].as_array().unwrap().is_empty());
    assert_eq!(std::fs::read_to_string(path).unwrap(), text);
    assert!(!root.path().join(".kuzushi/cpg-rs").exists());
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let descriptor = registry.resolve_tool("worklist:rank").unwrap();
    assert_eq!(descriptor.runtime_requirement, RuntimeRequirement::Never);
    assert!(!descriptor.phase_result);
}

#[test]
fn malformed_contributors_return_usable_partial_instead_of_complete() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join(".kuzushi")).unwrap();
    std::fs::write(crate::context::context_snapshot_path(root.path()), "{").unwrap();
    let result = dispatch(root.path(), json!({}), None).unwrap();
    assert_eq!(result["status"], "partial");
    assert!(!result["data"]["degraded"].as_array().unwrap().is_empty());
    assert!(result["data"]["systemsInspection"].is_null());
}

#[test]
fn pre_canceled_worklist_dispatch_refuses_without_new_evidence_or_jobs() {
    let root = tempfile::tempdir().unwrap();
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    assert!(dispatch(root.path(), json!({"deep":true}), Some(&cancellation)).is_err());
    assert!(!root.path().join(".kuzushi/cpg-rs").exists());
}
