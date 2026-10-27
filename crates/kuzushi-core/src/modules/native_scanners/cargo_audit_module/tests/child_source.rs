//! Labeled protocol controls qualify ownership separately from installed detection.
use super::*;
use crate::run_artifacts::{record_tool_run_started, ToolRunRecord, TraceHandle};

fn fixture() -> (tempfile::TempDir, WorkspaceTarget, FindingStore, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("README.md"), "Owned dependency metadata.\n").unwrap();
    for (child, note) in [("client\\scope", "literal"), ("client/scope", "nested")] {
        let path = source.join(child);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(
            path.join("Cargo.lock"),
            format!("# Owned {note} metadata, never built.\nversion = 3\n\n[[package]]\nname='owned'\nversion='1.0.0'\n"),
        )
        .unwrap();
    }
    let binary = executable(root.path(), FINDING);
    let workspace = WorkspaceTarget::new(source).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    (root, workspace, store, binary)
}

fn observed(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    binary: &Path,
    run: &str,
    child: &str,
) -> Value {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let config = V2Config::default();
    let input = json!({"target":child,"binary":binary,"offline":true,"timeoutMs":5000});
    let record = ToolRunRecord::new(workspace.root(), run, "tool", "cargo-audit:scan");
    record_tool_run_started(record, &input);
    let trace = TraceHandle::jsonl(workspace.root(), run);
    let ctx = ToolExecutionContext {
        trace: Some(&trace),
        ..context(workspace, &config, store)
    };
    let prepared = registry
        .prepare_dispatch_input("cargo-audit:scan", input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let execution = registry
        .dispatch_prepared_input_observed_with_runtime(prepared, &ctx, None)
        .unwrap();
    let output = execution.execution.unwrap();
    assert_eq!(output["status"], "completed", "{output:#}");
    crate::run_artifacts::try_record_tool_run_complete_settled(
        record,
        &output,
        &trace.run_observation().unwrap(),
        execution.completion,
    )
    .unwrap();
    output
}

fn assert_source(store: &FindingStore, path: &str, expected: &[u8]) {
    let findings = store.list_all_findings().unwrap();
    let finding = findings
        .iter()
        .find(|finding| finding.file_path == path)
        .expect(path);
    let source = store
        .recorded_observation_source(finding.id.unwrap())
        .unwrap()
        .unwrap();
    let bytes = store
        .read_observation_blob(source.blob_hash.as_ref().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(bytes, expected);
}

#[test]
fn child_cargo_workflow_identity_is_registered_in_the_parent_workspace() {
    let (_root, workspace, store, binary) = fixture();
    observed(&workspace, &store, &binary, "nested-child", "client/scope");
    let refs = vec!["nested-child".into()];
    let identity =
        crate::workflow_attempts::referenced_run_content_identity(workspace.root(), &refs);
    assert!(
        matches!(
            identity,
            crate::workflow_attempts::TargetContentIdentity::IndexedSnapshot { .. }
        ),
        "{identity:?}"
    );
    assert!(
        crate::workflow_attempts::referenced_runs_match_current_source(workspace.root(), &refs)
    );
    assert!(!workspace.root().join("client/scope/.kuzushi").exists());
}

#[test]
fn literal_and_nested_cargo_paths_keep_separate_sources_and_authenticated_coverage() {
    let (_root, workspace, store, binary) = fixture();
    for (run, child) in [
        ("literal-child", "client\\scope"),
        ("nested-child", "client/scope"),
    ] {
        let output = observed(&workspace, &store, &binary, run, child);
        let file = format!("{child}/Cargo.lock");
        assert_eq!(output["data"]["coreFindings"][0]["file_path"], file);
        assert_source(
            &store,
            &file,
            &std::fs::read(workspace.root().join(&file)).unwrap(),
        );
        let receipt = crate::run_artifacts::load_scan_stage_data(workspace.root(), run)
            .unwrap()
            .unwrap();
        let scope = receipt.scan.unwrap().scope;
        assert_eq!(scope.paths, [file.clone()]);
        assert_eq!(scope.inspected_files.unwrap(), [file].into());
    }
    let findings = store.list_all_findings().unwrap();
    assert_eq!(findings.len(), 2);
    assert_ne!(findings[0].fingerprint, findings[1].fingerprint);
}

#[test]
fn direct_and_scoped_cargo_agree_on_the_literal_child_identity() {
    let (_root, workspace, store, binary) = fixture();
    let direct = observed(
        &workspace,
        &store,
        &binary,
        "literal-direct",
        "client\\scope",
    );
    let config = V2Config::default();
    let ctx = context(&workspace, &config, &store);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let input = registry
        .prepare_dispatch_input(
            "sast:scan",
            json!({"taskMode":"manual",
        "tasks":["cargo-audit"],"paths":["client\\scope"],"cargoAuditBinary":binary,
        "cargoAuditOffline":true,"triage":false,"verify":false,"autoPatch":false}),
            &ctx,
            None,
        )
        .unwrap()
        .authorize_explicit_headless();
    let output = registry
        .dispatch_prepared_input_with_runtime(input, &ctx, None)
        .unwrap();
    assert_eq!(output["status"], "completed", "{output:#}");
    let findings = store.list_all_findings().unwrap();
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(findings[0].file_path, "client\\scope/Cargo.lock");
    assert_eq!(
        findings[0].fingerprint,
        direct["data"]["coreFindings"][0]["fingerprint"]
    );
}

#[test]
fn a_parent_edit_during_child_cargo_inspection_keeps_the_run_partial() {
    let (root, workspace, store, _) = fixture();
    let binary = source_editing_audit(root.path(), workspace.root(), FINDING);
    let config = V2Config::default();
    let ctx = context(&workspace, &config, &store);
    let output = run_cargo_audit_scan(
        json!({"target":"client/scope","binary":binary,"offline":true}),
        &ctx,
    )
    .unwrap();
    assert_eq!(output["status"], "partial", "{output:#}");
    assert_eq!(output["data"]["sourceCheckCurrent"], false);
    let run = output["data"]["persisted"]["runId"].as_str().unwrap();
    assert_eq!(store.run_status(run).unwrap().as_deref(), Some("partial"));
    assert_eq!(store.list_all_findings().unwrap().len(), 1);
    assert!(!workspace.root().join("client/scope/.kuzushi").exists());
}

#[test]
fn a_scoped_advisory_without_a_located_package_keeps_raw_observations_partial() {
    let (_root, workspace, store, binary) = fixture();
    std::fs::write(
        workspace.root().join("client/scope/Cargo.lock"),
        "version=3\n",
    )
    .unwrap();
    let config = V2Config::default();
    let ctx = context(&workspace, &config, &store);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let input = registry.prepare_dispatch_input("sast:scan", json!({"runId":"unlocated-cargo",
        "taskMode":"manual","tasks":["cargo-audit"],"paths":["client/scope"],
        "cargoAuditBinary":binary,"cargoAuditOffline":true,"triage":false,"verify":false,"autoPatch":false}), &ctx, None)
        .unwrap().authorize_explicit_headless();
    let output = registry
        .dispatch_prepared_input_with_runtime(input, &ctx, None)
        .unwrap();
    assert_eq!(output["status"], "partial", "{output:#}");
    assert!(output["output"]
        .as_str()
        .unwrap()
        .contains("no recorded line"));
    let findings = store.list_all_findings().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].start_line, 0);
    assert!(findings[0].message.contains("location is unavailable"));
    assert_eq!(
        store.run_status("unlocated-cargo").unwrap().as_deref(),
        Some("partial")
    );
}
