use kuzushi_core::{
    ModuleRegistry, SbomScanReport, ScanCancellation, ToolExecutionContext, V2Config,
    WorkspaceTarget,
};
use serde_json::{json, Value};
use std::path::Path;

#[path = "sbom_inventory_contract/pnpm.rs"]
mod pnpm;

fn dispatch(
    root: &Path,
    input: Value,
    cancellation: Option<&ScanCancellation>,
) -> anyhow::Result<Value> {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let workspace = WorkspaceTarget::new(root)?;
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation,
        authorization: Default::default(),
    };
    let input = registry
        .prepare_dispatch_input("sbom-scan:scan", input, &ctx, None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(input, &ctx, None)
}

#[test]
fn inventory_is_an_auxiliary_map_action_and_dag_metadata_does_not_add_a_prerequisite() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let descriptor = registry.resolve_tool("sbom-scan:scan").unwrap();
    assert_eq!(descriptor.phase, kuzushi_core::modules::ToolPhase::Map);
    assert!(!descriptor.phase_result);
    assert_eq!(kuzushi_core::modules::phase_result_phase(descriptor), None);
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"owned-library":"^1.0"}}"#,
    )
    .unwrap();
    assert!(!kuzushi_core::context_snapshot_path(root.path()).exists());
    let result = dispatch(root.path(), json!({}), None).unwrap();
    assert_eq!(result["status"], "completed");
    let events = kuzushi_core::workflow_attempts::load_phase_attempt_ledger(root.path()).unwrap();
    assert_eq!(events.attempts().count(), 0);
}

#[test]
fn shared_dispatch_preserves_declared_and_resolved_components_and_export_formats() {
    let root = tempfile::tempdir().unwrap();
    let manifest = r#"{"name":"owned-fixture","dependencies":{"owned-library":"^1.0"}}"#;
    let lock = r#"{"name":"owned-fixture","lockfileVersion":3,"packages":{"":{"dependencies":{"owned-library":"^1.0"}},"node_modules/owned-library":{"version":"1.2.3"}}}"#;
    std::fs::write(root.path().join("package.json"), manifest).unwrap();
    std::fs::write(root.path().join("package-lock.json"), lock).unwrap();
    let result = dispatch(root.path(), json!({}), None).unwrap();
    assert_eq!(result["status"], "completed");
    let report: SbomScanReport = serde_json::from_value(result["data"].clone()).unwrap();
    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.lockfiles.len(), 1);
    assert!(report
        .components
        .iter()
        .any(|item| item.name == "owned-library" && item.version.as_deref() == Some("^1.0")));
    assert!(report
        .components
        .iter()
        .any(|item| item.name == "owned-library" && item.version.as_deref() == Some("1.2.3")));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.to.contains("owned-library")));
    assert_eq!(result["data"]["cycloneDx"]["bomFormat"], "CycloneDX");
    assert_eq!(result["data"]["spdx"]["spdxVersion"], "SPDX-2.3");
    assert!(result.pointer("/data/coreFindings").is_none());
    assert_eq!(
        std::fs::read_to_string(root.path().join("package.json")).unwrap(),
        manifest
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("package-lock.json")).unwrap(),
        lock
    );
}

#[test]
fn invalid_input_and_malformed_manifests_are_honest_failures_without_fabricated_inventory() {
    let root = tempfile::tempdir().unwrap();
    assert!(dispatch(root.path(), json!({"recurse":true}), None).is_err());
    std::fs::write(root.path().join("package.json"), "{invalid}").unwrap();
    let result = dispatch(root.path(), json!({}), None).unwrap();
    assert_eq!(result["status"], "failed");
    assert!(result.pointer("/data/components").is_none());
    let cancellation = ScanCancellation::default();
    cancellation.cancel();
    assert!(dispatch(root.path(), json!({}), Some(&cancellation)).is_err());
}

#[test]
fn excessive_depth_fails_instead_of_claiming_complete_inventory() {
    let root = tempfile::tempdir().unwrap();
    let mut nested = root.path().to_path_buf();
    for _ in 0..65 {
        nested.push("d");
    }
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("package.json"), "{}").unwrap();
    let result = dispatch(root.path(), json!({}), None).unwrap();
    assert_eq!(result["status"], "failed");
    assert!(result.to_string().contains("64"));
    assert!(result.pointer("/data/components").is_none());
}

#[test]
fn oversized_manifest_fails_before_parsing_or_fabricating_components() {
    let root = tempfile::tempdir().unwrap();
    let file = std::fs::File::create(root.path().join("package.json")).unwrap();
    file.set_len(64 * 1024 * 1024 + 1).unwrap();
    let result = dispatch(root.path(), json!({}), None).unwrap();
    assert_eq!(result["status"], "failed");
    assert!(result.to_string().contains("67108864"));
    assert!(result.pointer("/data/components").is_none());
}

#[cfg(unix)]
#[test]
fn selected_target_excludes_parent_manifests_and_symlink_cycles() {
    let root = tempfile::tempdir().unwrap();
    let selected = root.path().join("service");
    std::fs::create_dir(&selected).unwrap();
    std::fs::write(root.path().join("package.json"), "{invalid parent}").unwrap();
    std::fs::write(
        selected.join("package.json"),
        r#"{"dependencies":{"owned-library":"^1.0"}}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(root.path(), selected.join("cycle")).unwrap();
    let result = dispatch(root.path(), json!({"target":selected}), None).unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["manifestsScanned"], 1);
    assert_eq!(result["data"]["components"][0]["name"], "owned-library");
}
