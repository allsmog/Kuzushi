use super::*;

fn dispatch(root: &Path, input: Value) -> Value {
    let workspace = crate::WorkspaceTarget::new(root).unwrap();
    let config = crate::V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    registry
        .execute_tool("sbom-scan:scan", input, &ctx)
        .unwrap()
}

#[test]
fn prepared_budget_is_shared_across_lock_digest_edges_and_components() {
    let root = tempfile::tempdir().unwrap();
    let text = "version = 3\n[[package]]\nname = \"owned\"\nversion = \"1.2.3\"\n";
    std::fs::write(root.path().join("Cargo.lock"), text).unwrap();
    let result = dispatch(
        root.path(),
        json!({"maxTotalBytes":text.len(),"maxFileBytes":text.len()}),
    );
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["componentCount"], 1);
    let inspection = &result["data"]["inspection"];
    assert_eq!(inspection["capturedFiles"], 1);
    assert_eq!(inspection["sourceBytesRead"], text.len());
    assert_eq!(inspection["reservedSourceBytes"], text.len());
    assert_eq!(
        inspection["inputs"][0]["sha256"],
        result["data"]["lockfiles"][0]["sha256"]
    );
}

#[test]
fn failed_inventory_retains_budget_evidence_and_no_package_claims() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"owned":"1.0"}}"#,
    )
    .unwrap();
    let result = dispatch(root.path(), json!({"maxTotalBytes":2}));
    assert_eq!(result["status"], "failed");
    assert!(result.to_string().contains("maxTotalBytes 2"));
    assert_eq!(result["data"]["inspection"]["sourceBytesRead"], 0);
    assert!(result.pointer("/data/components").is_none());
}

#[test]
fn descriptors_reject_invalid_limits_before_execution() {
    let registry = ModuleRegistry::with_v2_builtins();
    for input in [
        json!({"maxTotalBytes":0}),
        json!({"maxTotalBytes":MAX_SBOM_TOTAL_BYTES+1}),
        json!({"maxFileBytes":0}),
        json!({"maxFileBytes":MAX_SBOM_FILE_BYTES+1}),
        json!({"max_total_bytes":100}),
    ] {
        assert!(registry
            .prepare_tool_input("sbom-scan:scan", input, None)
            .is_err());
    }
    let prepared = registry
        .prepare_tool_input("sbom-scan:scan", json!({}), None)
        .unwrap();
    assert_eq!(prepared["maxTotalBytes"], DEFAULT_SBOM_TOTAL_BYTES);
    assert_eq!(prepared["maxFileBytes"], MAX_SBOM_FILE_BYTES);
}

#[test]
fn incomplete_utf8_is_not_parsed_as_a_complete_manifest() {
    let root = tempfile::tempdir().unwrap();
    let mut bytes = br#"{"dependencies":{}}"#.to_vec();
    bytes.push(0xe2);
    std::fs::write(root.path().join("package.json"), &bytes).unwrap();
    let result = dispatch(root.path(), json!({}));
    assert_eq!(result["status"], "failed");
    assert_eq!(result["data"]["inspection"]["capturedBytes"], bytes.len());
}

#[test]
fn referenced_import_maps_share_the_same_aggregate_allowance() {
    let root = tempfile::tempdir().unwrap();
    let config = r#"{"importMap":"./dependencies.json"}"#;
    let imports = r#"{"imports":{"owned":"npm:owned@1.2.3"}}"#;
    std::fs::write(root.path().join("deno.json"), config).unwrap();
    std::fs::write(root.path().join("dependencies.json"), imports).unwrap();
    let total = config.len() + imports.len();
    let result = dispatch(root.path(), json!({"maxTotalBytes":total}));
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["componentCount"], 1);
    assert_eq!(result["data"]["inspection"]["capturedFiles"], 2);
    assert_eq!(result["data"]["inspection"]["sourceBytesRead"], total);
    let refused = dispatch(root.path(), json!({"maxTotalBytes":total-1}));
    assert_eq!(refused["status"], "failed");
    assert!(refused.pointer("/data/components").is_none());
    assert_eq!(
        refused["data"]["inspection"]["sourceBytesRead"],
        config.len()
    );
}

#[test]
fn unsupported_package_shapes_fail_without_inventing_an_empty_inventory() {
    for text in [
        "[]",
        "null",
        r#"{"dependencies":["owned"]}"#,
        r#"{"devDependencies":null}"#,
        r#"{"peerDependencies":{"owned":42}}"#,
        r#"{"optionalDependencies":{"owned":{"version":false}}}"#,
    ] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("package.json"), text).unwrap();
        let result = dispatch(root.path(), json!({}));
        assert_eq!(result["status"], "failed", "{text}: {result}");
        assert!(result.to_string().contains("package.json"));
        assert_eq!(result["data"]["inspection"]["capturedBytes"], text.len());
        assert!(result.pointer("/data/components").is_none());
        assert!(result.pointer("/data/dependencies").is_none());
        assert_eq!(std::fs::read_to_string(root.path().join("package.json")).unwrap(), text);
    }
}

#[test]
fn string_specs_and_legacy_version_objects_keep_matching_components_and_edges() {
    let root = tempfile::tempdir().unwrap();
    let text = json!({
        "dependencies": {"empty": "", "alias": "npm:owned@^1", "local": "file:../shared"},
        "devDependencies": {"git": "git+https://example.test/owned.git#main"},
        "peerDependencies": {"web": "https://example.test/owned.tgz"},
        "optionalDependencies": {"compat": {"version": "^2", "optional": true}}
    }).to_string();
    std::fs::write(root.path().join("package.json"), &text).unwrap();
    let result = dispatch(root.path(), json!({}));
    assert_eq!(result["status"], "completed", "{result}");
    let components = result["data"]["components"].as_array().unwrap();
    let edges = result["data"]["dependencies"].as_array().unwrap();
    assert_eq!(components.len(), 6);
    assert_eq!(edges.len(), 6);
    for component in components {
        assert!(edges.iter().any(|edge| edge["to"] == component["name"]));
    }
    assert!(components.iter().any(|row| row["name"] == "empty" && row["version"] == ""));
    assert!(components.iter().any(|row| row["name"] == "compat" && row["version"] == "^2"));
}

#[test]
fn an_unsupported_child_does_not_publish_parent_packages_and_can_be_corrected() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("package.json"), r#"{"dependencies":{"parent":"1"}}"#).unwrap();
    let child = root.path().join("packages/child/package.json");
    std::fs::create_dir_all(child.parent().unwrap()).unwrap();
    std::fs::write(&child, r#"{"devDependencies":{"child":42}}"#).unwrap();
    let result = dispatch(root.path(), json!({}));
    assert_eq!(result["status"], "failed", "{result}");
    assert!(result.to_string().contains("packages/child/package.json: devDependencies.child"));
    assert_eq!(result["data"]["inspection"]["capturedFiles"], 2);
    assert!(result.pointer("/data/components").is_none());
    assert!(result.pointer("/data/cycloneDx").is_none());
    assert!(result.pointer("/data/spdx").is_none());
    std::fs::write(&child, r#"{"devDependencies":{"child":"2"}}"#).unwrap();
    let corrected = dispatch(root.path(), json!({}));
    assert_eq!(corrected["status"], "completed", "{corrected}");
    assert_eq!(corrected["data"]["componentCount"], 2);
}
