use crate::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};

fn dispatch(workspace: &WorkspaceTarget, tool: &str, input: Value) -> anyhow::Result<Value> {
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry.prepare_dispatch_input(tool, input, &ctx, None)?;
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}

fn write_manifest(root: &std::path::Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{"dependencies":{"owned-package":"1.0.0"}}"#,
    )
    .unwrap();
}

#[test]
fn candidate_extraction_is_opt_in_and_readers_do_not_complete_map() {
    let registry = ModuleRegistry::with_v2_builtins();
    assert!(!registry.tool_is_discoverable("threat-intel:discover"));
    assert!(registry.tool_is_discoverable("threat-intel:list"));
    for name in ["threat-intel:discover", "threat-intel:list"] {
        let descriptor = registry.resolve_tool(name).unwrap();
        assert!(descriptor.headless);
        assert!(!descriptor.phase_result);
        assert_eq!(crate::modules::phase_result_phase(descriptor), None);
    }
}

#[test]
fn mixed_manifests_keep_candidates_and_disclose_the_nested_coverage_gap() {
    let root = tempfile::tempdir().unwrap();
    write_manifest(root.path());
    std::fs::create_dir(root.path().join("service")).unwrap();
    std::fs::write(
        root.path().join("service/go.mod"),
        "module example.invalid/owned\nrequire example.invalid/library v1.2.3\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let result = dispatch(&workspace, "threat-intel:discover", json!({})).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["packageCount"], 1);
    assert_eq!(result["data"]["coverage"]["complete"], false);
    assert!(result["summary"]
        .as_str()
        .unwrap()
        .contains("sbom-scan:scan"));
    let path = result["data"]["outputPath"].as_str().unwrap();
    let stored: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(stored["coverage"], result["data"]["coverage"]);
    assert_eq!(stored["packages"].as_array().unwrap().len(), 1);
    assert!(!crate::context::context_snapshot_path(workspace.root()).exists());
    let sbom = dispatch(&workspace, "sbom-scan:scan", json!({})).unwrap();
    assert_eq!(sbom["data"]["componentCount"], 2);
}

#[test]
fn empty_candidates_are_partial_and_explain_the_next_action() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let result = dispatch(&workspace, "threat-intel:discover", json!({})).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["packageCount"], 0);
    assert!(result["summary"]
        .as_str()
        .unwrap()
        .contains("No package candidates"));
}

#[test]
fn malformed_manifest_does_not_replace_the_previous_candidates() {
    let root = tempfile::tempdir().unwrap();
    write_manifest(root.path());
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let first = dispatch(&workspace, "threat-intel:discover", json!({})).unwrap();
    let path = first["data"]["outputPath"].as_str().unwrap();
    let before = std::fs::read(path).unwrap();
    std::fs::write(root.path().join("package.json"), "{invalid").unwrap();
    let error = dispatch(&workspace, "threat-intel:discover", json!({})).unwrap_err();
    assert!(format!("{error:#}").contains("package.json"));
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn candidate_extraction_rejects_unknown_options_before_writing() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    assert!(dispatch(
        &workspace,
        "threat-intel:discover",
        json!({"recurse": true})
    )
    .is_err());
    assert!(!root
        .path()
        .join(".kuzushi/threat-intel/candidates.json")
        .exists());
}

#[test]
fn catalog_reader_distinguishes_missing_empty_and_malformed_documents() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    assert!(dispatch(&workspace, "threat-intel:list", json!({})).is_err());
    let path = root.path().join(".kuzushi/catalogs/owned.toml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "schema_version = \"1\"\n").unwrap();
    let result = dispatch(&workspace, "threat-intel:list", json!({})).unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["summary"]["totalEntries"], 0);
    std::fs::write(&path, "invalid = [").unwrap();
    let error = dispatch(&workspace, "threat-intel:list", json!({})).unwrap_err();
    assert!(format!("{error:#}").contains("invalid TOML"));
}

#[test]
fn catalog_reader_preserves_nonempty_metadata_without_dispatching_entries() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let path = root.path().join("owned.toml");
    std::fs::write(&path, "schema_version = \"1\"\n[[entry]]\nid = \"owned-entry\"\ntitle = \"Owned catalog note\"\ncwe = \"CWE-20\"\nseverity = \"low\"\nhunt = \"owned-inert\"\n").unwrap();
    let result = dispatch(
        &workspace,
        "threat-intel:list",
        json!({"catalogPath": path}),
    )
    .unwrap();
    assert_eq!(result["data"]["summary"]["totalEntries"], 1);
    assert_eq!(result["data"]["entries"][0]["id"], "owned-entry");
    assert_eq!(result["data"]["entries"][0]["hunt"], "owned-inert");
    assert!(!root
        .path()
        .join(".kuzushi/threat-intel/candidates.json")
        .exists());
}

#[cfg(unix)]
#[test]
fn symlinked_input_does_not_gain_inventory_or_catalog_read_access() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    write_manifest(outside.path());
    std::os::unix::fs::symlink(
        outside.path().join("package.json"),
        root.path().join("package.json"),
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    assert!(dispatch(&workspace, "threat-intel:discover", json!({})).is_err());
    let catalog = outside.path().join("owned.toml");
    std::fs::write(&catalog, "schema_version = \"1\"\n").unwrap();
    assert!(dispatch(
        &workspace,
        "threat-intel:list",
        json!({"catalogPath": catalog})
    )
    .is_err());
}
