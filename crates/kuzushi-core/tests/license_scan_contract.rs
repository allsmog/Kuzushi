use kuzushi_core::{
    FindingStore, ModuleRegistry, ScanCancellation, ToolExecutionContext, V2Config, WorkspaceTarget,
};
use serde_json::{json, Value};
use std::path::Path;

fn dispatch(root: &Path, tool: &str, input: Value) -> anyhow::Result<(FindingStore, Value)> {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let workspace = WorkspaceTarget::new(root)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input(tool, input, &ctx, None)?
        .authorize_explicit_headless();
    let result = registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)?;
    Ok((store, result))
}

fn licensed_package(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"owned-policy-fixture","license":"MIT"}"#,
    )
    .unwrap();
    std::fs::write(root.join("LICENSE"), "MIT License\n").unwrap();
}

#[test]
fn scanner_persists_real_signal_only_findings_without_a_model_or_context() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("package.json"),
        r#"{"name":"owned-policy-fixture"}"#,
    )
    .unwrap();
    let (store, result) = dispatch(root.path(), "license-scan:scan", json!({})).unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["count"], 1);
    assert!(
        result["data"]["treeHash"]
            .as_str()
            .is_some_and(|hash| !hash.is_empty()),
        "{result}"
    );
    let finding = store.list_findings(10).unwrap().remove(0);
    assert_eq!(finding.tool, "license-scan");
    assert_eq!(finding.rule_id, "license-scan/missing-license");
    assert_eq!(
        finding.static_proof_state,
        Some(kuzushi_core::StaticProofState::SignalOnly)
    );
    assert!(!kuzushi_core::context_snapshot_path(root.path()).exists());
}

#[test]
fn internal_analysis_artifacts_are_outside_source_header_policy() {
    let root = tempfile::tempdir().unwrap();
    licensed_package(root.path());
    std::fs::create_dir_all(root.path().join(".kuzushi/generated")).unwrap();
    std::fs::write(
        root.path().join(".kuzushi/generated/receipt.rs"),
        "// Internal fixture artifact.\n",
    )
    .unwrap();
    let (store, result) = dispatch(
        root.path(),
        "license-scan:scan",
        json!({"requireSpdxHeaders":true}),
    )
    .unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["count"], 0);
    assert!(store.list_findings(10).unwrap().is_empty());
}

#[test]
fn unreadable_license_extent_cannot_become_a_clean_result() {
    let root = tempfile::tempdir().unwrap();
    licensed_package(root.path());
    let file = std::fs::File::create(root.path().join("LICENSE")).unwrap();
    file.set_len(2 * 1024 * 1024 + 1).unwrap();
    let (store, result) = dispatch(root.path(), "license-scan:scan", json!({})).unwrap();
    assert_eq!(result["status"], "failed");
    assert!(result.to_string().contains("2097152"), "{result}");
    assert!(result.pointer("/data/coreFindings").is_none());
    assert!(store.list_findings(10).unwrap().is_empty());
}

#[test]
fn excessive_depth_returns_a_failure_without_persisting_findings() {
    let root = tempfile::tempdir().unwrap();
    let mut nested = root.path().to_path_buf();
    for _ in 0..65 {
        nested.push("d");
    }
    std::fs::create_dir_all(&nested).unwrap();
    licensed_package(&nested);
    let (store, result) = dispatch(root.path(), "license-scan:scan", json!({})).unwrap();
    assert_eq!(result["status"], "failed");
    assert!(result.to_string().contains("64"), "{result}");
    assert!(store.list_findings(10).unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn external_license_symlink_is_excluded_instead_of_manufacturing_mismatch_evidence() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    licensed_package(root.path());
    std::fs::remove_file(root.path().join("LICENSE")).unwrap();
    std::fs::write(outside.path().join("LICENSE"), "GPL-3.0-only\n").unwrap();
    std::os::unix::fs::symlink(outside.path().join("LICENSE"), root.path().join("LICENSE"))
        .unwrap();
    let (_, result) = dispatch(root.path(), "license-scan:scan", json!({})).unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(
        result["data"]["findings"][0]["ruleId"],
        "license-scan/missing-license-file"
    );
    assert!(!result.to_string().contains("license-file-mismatch"));
}

#[test]
fn invalid_options_and_cancelled_work_are_refused_without_findings() {
    let root = tempfile::tempdir().unwrap();
    assert!(dispatch(root.path(), "license-scan:scan", json!({"unknown":true})).is_err());
    let cancellation = ScanCancellation::default();
    cancellation.cancel();
    assert!(kuzushi_core::scan_licenses(root.path(), &cancellation).is_err());
}

#[test]
fn scan_umbrella_persists_the_same_signal_and_rejects_file_scope_widening() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("service")).unwrap();
    std::fs::write(
        root.path().join("service/package.json"),
        r#"{"name":"owned-service"}"#,
    )
    .unwrap();
    std::fs::write(root.path().join("package.json"), "{invalid parent}").unwrap();
    let input = json!({"taskMode":"manual","tasks":["license-scan"],"paths":["service"],"verify":false,"autoPatch":false,"runId":"owned-license-scope"});
    let (store, result) = dispatch(root.path(), "sast:scan", input).unwrap();
    assert_eq!(result["status"], "completed", "{result}");
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "license-scan");
    assert_eq!(findings[0].file_path, "service/package.json");
    let input = json!({"taskMode":"manual","tasks":["license-scan"],"paths":["service/package.json"],"verify":false,"autoPatch":false});
    assert!(dispatch(root.path(), "sast:scan", input).is_err());
}

#[test]
fn a_truncated_source_prefix_cannot_fabricate_a_missing_header_observation() {
    let root = tempfile::tempdir().unwrap();
    licensed_package(root.path());
    std::fs::write(root.path().join("source.rs"), "//".repeat(40_000)).unwrap();
    let (store, result) = dispatch(
        root.path(),
        "license-scan:scan",
        json!({"requireSourceSpdxHeaders":true}),
    )
    .unwrap();
    assert_eq!(result["status"], "failed", "{result}");
    assert!(result.to_string().contains("header absence is unverified"));
    assert!(store.list_findings(10).unwrap().is_empty());
}
