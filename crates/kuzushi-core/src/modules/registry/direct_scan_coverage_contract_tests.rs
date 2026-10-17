use crate::run_artifacts::{
    record_tool_run_started, try_record_tool_run_complete_settled, ToolRunRecord, TraceHandle,
};
use crate::{FindingStore, ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::{fs, path::Path};

fn dispatch(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run: &str,
    tool: &str,
    input: Value,
) -> Value {
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let trace = TraceHandle::jsonl(workspace.root(), run);
    let record = ToolRunRecord::new(workspace.root(), run, "tool", tool);
    record_tool_run_started(record, &input);
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: Some(&trace),
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input(tool, input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let observation = ctx.run_observation().unwrap();
    let dispatched = registry
        .dispatch_prepared_input_observed_with_runtime(prepared, &ctx, None)
        .unwrap();
    let output = dispatched.execution.unwrap();
    try_record_tool_run_complete_settled(record, &output, &observation, dispatched.completion)
        .unwrap();
    output
}

fn receipt(workspace: &WorkspaceTarget, run: &str) -> crate::run_artifacts::PhaseStageReceipt {
    crate::run_artifacts::load_scan_stage_data(workspace.root(), run)
        .unwrap()
        .expect("A supported direct scan needs authenticated scope and coverage")
}

#[test]
fn direct_iac_records_selected_scope_enabled_rules_and_observation_artifact() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("selected")).unwrap();
    fs::write(
        root.path().join("selected/Dockerfile"),
        "FROM owned:latest\nUSER nobody\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let output = dispatch(
        &workspace,
        &store,
        "selected-iac",
        "iac-scan:scan",
        json!({"target":"selected","kind":"dockerfile"}),
    );
    assert_eq!(output["status"], "completed");
    let stage = receipt(&workspace, "selected-iac");
    let scan = stage.scan.unwrap();
    assert_eq!(scan.scope.target, workspace.root().display().to_string());
    assert_eq!(scan.scope.paths, vec!["selected"]);
    assert!(!scan.scope.covers_file("Dockerfile"));
    assert!(scan.scope.covers_file("selected/Dockerfile"));
    assert!(scan.engines[0]
        .rule_ids
        .as_ref()
        .unwrap()
        .iter()
        .all(|id| id.starts_with("iac-scan/dockerfile-")));
    assert_eq!(scan.artifact_delta[0].path, "findings.json");
    assert_eq!(scan.finding_delta.added, 1);
}

#[test]
fn direct_empty_iac_publishes_an_empty_snapshot_with_no_invented_rules() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    dispatch(
        &workspace,
        &store,
        "empty-iac",
        "iac-scan:scan",
        json!({"kind":"terraform"}),
    );
    let scan = receipt(&workspace, "empty-iac").scan.unwrap();
    assert!(scan.engines[0]
        .rule_ids
        .as_ref()
        .unwrap()
        .iter()
        .all(|id| id.starts_with("iac-scan/terraform-")));
    let (_, body) = crate::run_artifacts::read_run_artifact_text(
        workspace.root(),
        "empty-iac",
        "findings.json",
    )
    .require("observations")
    .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), json!([]));
}

#[cfg(unix)]
fn audit_protocol(folder: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = folder.join("owned-advisory-protocol.sh");
    fs::write(&path,r#"#!/bin/sh
cat >/dev/null
printf '%s' '{"vulnerabilities":{"found":true,"list":[{"advisory":{"id":"RUSTSEC-OWNED-1","title":"Owned metadata observation"},"package":{"name":"owned","version":"1.0.0"}}]}}'
exit 1
"#).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[cfg(unix)]
#[test]
fn direct_cargo_records_only_its_lockfile_and_separates_selected_identities() {
    let root = tempfile::tempdir().unwrap();
    let adapter = tempfile::tempdir().unwrap();
    let binary = audit_protocol(adapter.path());
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    for name in ["a", "b"] {
        fs::create_dir(root.path().join(name)).unwrap();
        fs::write(
            root.path().join(name).join("Cargo.lock"),
            "# Owned inert metadata\nversion=3\n",
        )
        .unwrap();
        let run = format!("audit-{name}");
        dispatch(
            &workspace,
            &store,
            &run,
            "cargo-audit:scan",
            json!({"target":name,"binary":binary,"offline":true}),
        );
        let scan = receipt(&workspace, &run).scan.unwrap();
        assert_eq!(scan.scope.paths, vec![format!("{name}/Cargo.lock")]);
        assert!(!scan.scope.covers_file(&format!("{name}/nested/Cargo.lock")));
        assert!(scan.engines[0].rule_ids.is_none());
    }
    let findings = store.list_all_findings().unwrap();
    assert_eq!(
        findings.len(),
        2,
        "Different selected lockfiles must keep separate identities"
    );
    assert_ne!(findings[0].file_path, findings[1].file_path);
}

#[test]
fn disabled_iac_family_and_uninspected_files_never_create_observation_gaps() {
    use crate::findings::{compare_scan_runs, ScanObservationPresence};
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join(".github/workflows")).unwrap();
    fs::write(
        root.path().join(".github/workflows/owned.yml"),
        "permissions: write-all\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    dispatch(&workspace, &store, "all-iac", "iac-scan:scan", json!({}));
    let findings = store.list_all_findings().unwrap();
    assert_eq!(findings.len(), 1);
    dispatch(
        &workspace,
        &store,
        "docker-only",
        "iac-scan:scan",
        json!({"kind":"dockerfile"}),
    );
    assert!(store.list_all_findings().unwrap()[0]
        .observation_gap
        .is_none());
    let scan = receipt(&workspace, "docker-only").scan.unwrap();
    assert!(scan.scope.inspected_files.unwrap().is_empty());
    let comparison = compare_scan_runs(&store, "all-iac", "docker-only").unwrap();
    assert_eq!(
        comparison.findings[0].observation_presence(),
        ScanObservationPresence::NotReassessed
    );
}

#[cfg(unix)]
#[test]
fn changed_cargo_advisory_output_without_recorded_policy_does_not_retire_a_signal() {
    use crate::findings::{compare_scan_runs, ScanObservationPresence};
    let root = tempfile::tempdir().unwrap();
    let adapter = tempfile::tempdir().unwrap();
    let binary = audit_protocol(adapter.path());
    fs::write(
        root.path().join("Cargo.lock"),
        "# Owned inert metadata\nversion=3\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let input = json!({"binary":binary,"offline":true});
    dispatch(
        &workspace,
        &store,
        "advisory-base",
        "cargo-audit:scan",
        input.clone(),
    );
    fs::write(&binary, "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"vulnerabilities\":{\"found\":false,\"list\":[]}}'\n").unwrap();
    dispatch(
        &workspace,
        &store,
        "advisory-empty",
        "cargo-audit:scan",
        input,
    );
    assert!(store.list_all_findings().unwrap()[0]
        .observation_gap
        .is_none());
    let comparison = compare_scan_runs(&store, "advisory-base", "advisory-empty").unwrap();
    assert_eq!(
        comparison.findings[0].observation_presence(),
        ScanObservationPresence::NotReassessed
    );
}

#[cfg(unix)]
#[test]
fn an_excluded_file_is_not_reassessed_even_when_its_rule_family_remains_enabled() {
    use crate::findings::{compare_scan_runs, ScanObservationPresence};
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let file = root.path().join("Dockerfile");
    fs::write(&file, "FROM owned:latest\nUSER nobody\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    dispatch(
        &workspace,
        &store,
        "file-inspected",
        "iac-scan:scan",
        json!({"kind":"dockerfile"}),
    );
    fs::rename(&file, outside.path().join("Dockerfile")).unwrap();
    std::os::unix::fs::symlink(outside.path().join("Dockerfile"), &file).unwrap();
    let output = dispatch(
        &workspace,
        &store,
        "file-excluded",
        "iac-scan:scan",
        json!({"kind":"dockerfile"}),
    );
    assert_eq!(output["status"], "completed");
    let scan = receipt(&workspace, "file-excluded").scan.unwrap();
    assert_eq!(scan.scope.inspected_files.unwrap().len(), 0);
    assert!(!scan.engines[0].rule_ids.as_ref().unwrap().is_empty());
    assert!(store.list_all_findings().unwrap()[0]
        .observation_gap
        .is_none());
    let comparison = compare_scan_runs(&store, "file-inspected", "file-excluded").unwrap();
    assert_eq!(
        comparison.findings[0].observation_presence(),
        ScanObservationPresence::NotReassessed
    );
}
