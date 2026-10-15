use crate::{FindingStore, ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};

fn dispatch(workspace: &WorkspaceTarget, input: Value) -> Value {
    let config = V2Config::default();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input("dep-hygiene:check", input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap()
}

fn manifest(root: &std::path::Path, directory: &str, text: &str) {
    let dir = root.join(directory);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("package.json"), text).unwrap();
}

#[test]
fn whole_repository_hygiene_covers_loose_and_nested_manifests() {
    let root = tempfile::tempdir().unwrap();
    manifest(root.path(), "", r#"{"dependencies":{"root-example":"*"}}"#);
    manifest(
        root.path(),
        "service",
        r#"{"dependencies":{"child-example":"latest"}}"#,
    );
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let result = dispatch(&workspace, json!({}));
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["count"], 2);
    assert_eq!(result["data"]["inspection"]["manifestsInspected"], 2);
    assert!(result["data"]["snapshotHash"]
        .as_str()
        .is_some_and(|s| s.len() == 64));
}

#[test]
fn malformed_manifests_leave_a_partial_receipt_and_keep_other_observations() {
    let root = tempfile::tempdir().unwrap();
    manifest(
        root.path(),
        "a-valid",
        r#"{"dependencies":{"example":"*"}}"#,
    );
    manifest(root.path(), "z-invalid", "{ invalid");
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let result = dispatch(&workspace, json!({}));
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["count"], 1);
    assert_eq!(
        result["data"]["inspection"]["gaps"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("Incomplete inspection"));
}

#[test]
fn invalid_root_document_cannot_be_presented_as_a_clean_scan() {
    let root = tempfile::tempdir().unwrap();
    manifest(root.path(), "", "[]");
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let result = dispatch(&workspace, json!({}));
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["count"], 0);
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("Incomplete inspection"));
}

#[test]
fn explicit_child_target_does_not_read_the_parent_manifest() {
    let root = tempfile::tempdir().unwrap();
    manifest(root.path(), "", "{ invalid");
    manifest(root.path(), "child", r#"{"dependencies":{"example":"*"}}"#);
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let result = dispatch(&workspace, json!({"target":"child"}));
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["count"], 1);
    assert!(result["data"]["inspection"]["gaps"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn artifact_and_vendor_manifests_are_excluded_from_discovery() {
    let root = tempfile::tempdir().unwrap();
    for name in [".kuzushi", "node_modules", "target", "vendor"] {
        manifest(root.path(), name, r#"{"dependencies":{"excluded":"*"}}"#);
    }
    manifest(
        root.path(),
        "service",
        r#"{"dependencies":{"included":"*"}}"#,
    );
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let result = dispatch(&workspace, json!({}));
    assert_eq!(result["data"]["count"], 1);
    assert_eq!(result["data"]["findings"][0]["packageName"], "included");
}

#[test]
fn shared_scan_dispatch_retains_hygiene_observations_and_coverage_gaps() {
    let root = tempfile::tempdir().unwrap();
    manifest(root.path(), "valid", r#"{"dependencies":{"example":"*"}}"#);
    manifest(root.path(), "invalid", "{ invalid");
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
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input(
            "sast:scan",
            json!({
                "taskMode":"manual", "tasks":["dep-hygiene"], "triage":false,
                "verify":false, "autoPatch":false, "threatModelRef":null
            }),
            &ctx,
            None,
        )
        .unwrap()
        .authorize_explicit_headless();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(result["status"], "partial");
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("invalid JSON document"));
    assert!(result.to_string().contains("example"));
}
