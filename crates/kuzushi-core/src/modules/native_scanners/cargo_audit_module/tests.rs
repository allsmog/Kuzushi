use super::*;
use crate::{FindingStore, V2Config, WorkspaceTarget};

const FINDING: &str = r#"{"vulnerabilities":{"found":true,"list":[{"advisory":{"id":"RUSTSEC-OWNED-1","title":"Owned advisory fixture"},"package":{"name":"owned","version":"1.0.0"}}]}}"#;

#[cfg(unix)]
fn executable(folder: &Path, output: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let binary = folder.join("audit-fixture.sh");
    std::fs::write(
        &binary,
        format!("#!/bin/sh\ncat >/dev/null\nprintf '%s' '{output}'\nexit 1\n"),
    )
    .unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    binary
}

fn context<'a>(
    workspace: &'a WorkspaceTarget,
    config: &'a V2Config,
    store: &'a FindingStore,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    }
}

#[test]
fn cargo_audit_options_prepare_aliases_and_refuse_invalid_or_unused_controls() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = context(&workspace, &config, &store);
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input(
            "cargo-audit:scan",
            json!({"offline":true,"timeout_ms":300,"max_lockfile_bytes":128}),
            &ctx,
            None,
        )
        .unwrap();
    assert_eq!(prepared.value()["timeoutMs"], 300);
    assert_eq!(prepared.value()["maxLockfileBytes"], 128);
    let study = registry.prepare_dispatch_input("sast:scan",json!({"tasks":["cargo-audit"],"cargo_audit_offline":true,"cargo_audit_timeout_ms":300}),&ctx,None).unwrap();
    assert_eq!(study.value()["cargoAuditTimeoutMs"], 300);
    assert_eq!(study.value()["cargoAuditOffline"], true);
    assert!(registry
        .prepare_dispatch_input(
            "sast:scan",
            json!({"tasks":["license-scan"],"cargoAuditOffline":true}),
            &ctx,
            None
        )
        .unwrap_err()
        .to_string()
        .contains("require the cargo-audit task"));
    assert!(registry
        .prepare_dispatch_input("cargo-audit:scan", json!({"timeoutMs":0}), &ctx, None)
        .is_err());
    assert!(registry
        .prepare_dispatch_input(
            "cargo-audit:scan",
            json!({"undeclaredAuditSetting":true}),
            &ctx,
            None
        )
        .is_err());
}

#[cfg(unix)]
#[test]
fn cargo_audit_prepared_dispatch_persists_real_envelope_observations_and_source_receipts() {
    let fixture = tempfile::tempdir().unwrap();
    let source = fixture.path().join("source");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("Cargo.lock"), "# Owned metadata\nversion=3\n").unwrap();
    let binary = executable(fixture.path(), FINDING);
    let workspace = WorkspaceTarget::new(&source).unwrap();
    let config = V2Config::default();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = context(&workspace, &config, &store);
    let registry = ModuleRegistry::with_v2_builtins();
    let input = registry
        .prepare_dispatch_input(
            "cargo-audit:scan",
            json!({"binary":binary,"offline":true}),
            &ctx,
            None,
        )
        .unwrap();
    let output = registry
        .dispatch_prepared_input_with_runtime(input, &ctx, None)
        .unwrap();
    assert_eq!(
        crate::tool_result_status(&output),
        crate::ToolResultStatus::Completed
    );
    assert_eq!(output["data"]["count"], 1);
    assert_eq!(
        output["data"]["coreFindings"][0]["staticProofState"],
        "signal_only"
    );
    assert_eq!(output["data"]["nativeInspections"][0]["offline"], true);
    assert!(output["output"]
        .as_str()
        .unwrap()
        .contains("Nested lockfiles"));
    assert!(output["output"]
        .as_str()
        .unwrap()
        .contains("Advisory network: offline"));
    assert_eq!(store.list_all_findings().unwrap().len(), 1);
    let run = output["data"]["persisted"]["runId"].as_str().unwrap();
    assert_eq!(
        store
            .count_finding_observations_for_scan_ids(&[run])
            .unwrap(),
        1
    );
}

#[test]
fn cargo_audit_missing_lockfile_fails_instead_of_publishing_a_clean_scan() {
    let fixture = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(fixture.path()).unwrap();
    let config = V2Config::default();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = context(&workspace, &config, &store);
    let registry = ModuleRegistry::with_v2_builtins();
    let input = registry
        .prepare_dispatch_input("cargo-audit:scan", json!({"offline":true}), &ctx, None)
        .unwrap();
    let output = registry
        .dispatch_prepared_input_with_runtime(input, &ctx, None)
        .unwrap();
    assert_eq!(
        crate::tool_result_status(&output),
        crate::ToolResultStatus::Failed
    );
    assert!(output["output"]
        .as_str()
        .unwrap()
        .contains("regular Cargo.lock"));
    assert!(store.list_all_findings().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn direct_cargo_source_drift_keeps_positive_and_empty_runs_partial() {
    for report in [FINDING, r#"{"vulnerabilities":{"found":false,"list":[]}}"#] {
        let fixture = tempfile::tempdir().unwrap();
        let source = fixture.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("Cargo.lock"), "# Owned metadata\nversion=3\n").unwrap();
        let binary = source_editing_audit(fixture.path(), &source, report);
        let workspace = WorkspaceTarget::new(&source).unwrap();
        let config = V2Config::default();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let ctx = context(&workspace, &config, &store);
        let registry = ModuleRegistry::with_v2_builtins();
        let input = registry
            .prepare_dispatch_input(
                "cargo-audit:scan",
                json!({"binary":binary,"offline":true}),
                &ctx,
                None,
            )
            .unwrap();
        let output = registry
            .dispatch_prepared_input_with_runtime(input, &ctx, None)
            .unwrap();
        assert_eq!(output["status"], "partial", "{output:#}");
        let run = output["data"]["persisted"]["runId"].as_str().unwrap();
        assert_eq!(store.run_status(run).unwrap().as_deref(), Some("partial"));
        assert_eq!(
            store.list_all_findings().unwrap().len() as u64,
            output["data"]["count"].as_u64().unwrap()
        );
    }
}

#[cfg(unix)]
fn source_editing_audit(folder: &Path, source: &Path, report: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let binary = folder.join("owned-audit-protocol.sh");
    std::fs::write(&binary, format!(
        "#!/bin/sh\nif [ \"$1\" = '--version' ]; then printf 'cargo-audit owned fixture\\n'; exit 0; fi\ncat >/dev/null\nprintf 'Planned inert edit\\n' > '{}'\nprintf '%s' '{}'\n",
        source.join("planned-edit.txt").display(), report
    )).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    binary
}

#[cfg(unix)]
#[test]
fn cargo_audit_scoped_study_keeps_separate_lockfile_identities_and_refuses_exact_membership() {
    let fixture = tempfile::tempdir().unwrap();
    let source = fixture.path().join("source");
    std::fs::create_dir(&source).unwrap();
    for directory in ["a", "b"] {
        let directory = source.join(directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("Cargo.lock"),
            "# Owned metadata\nversion=3\n",
        )
        .unwrap();
    }
    let binary = executable(fixture.path(), FINDING);
    let workspace = WorkspaceTarget::new(&source).unwrap();
    let config = V2Config::default();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = context(&workspace, &config, &store);
    let registry = ModuleRegistry::with_v2_builtins();
    let input = registry.prepare_dispatch_input("sast:scan",json!({"taskMode":"manual","tasks":["cargo-audit"],"paths":["a","b"],"cargoAuditBinary":binary,"cargoAuditOffline":true}),&ctx,None).unwrap();
    let output = registry
        .dispatch_prepared_input_with_runtime(input, &ctx, None)
        .unwrap();
    assert_eq!(
        crate::tool_result_status(&output),
        crate::ToolResultStatus::Completed
    );
    let findings = store.list_all_findings().unwrap();
    assert_eq!(findings.len(), 2, "{output}");
    assert_ne!(findings[0].fingerprint, findings[1].fingerprint);
    assert!(findings
        .iter()
        .all(|f| f.file_path == "a/Cargo.lock" || f.file_path == "b/Cargo.lock"));
    assert!(registry
        .prepare_dispatch_input(
            "sast:scan",
            json!({"tasks":["cargo-audit"],"paths":["a/Cargo.lock"]}),
            &ctx,
            None
        )
        .is_err());
}
