use super::*;
use serde_json::{json, Value};

fn audit_result(app: &mut ShellApp, workspace: &WorkspaceTarget, input: Value) -> Value {
    run_command(app, ShellCommand::Use("cargo-audit".into()));
    run_command(
        app,
        ShellCommand::RunTool {
            tool: None,
            input: Some(input.to_string()),
        },
    );
    drain_tool(app);
    let run = &app.activity().unwrap().run_id;
    let result = run_dir(workspace.root(), run).join("result.json");
    serde_json::from_slice(&fs::read(result).unwrap()).unwrap()
}

fn assert_recorded_status(app: &ShellApp, workspace: &WorkspaceTarget, status: &str) {
    let run = &app.activity().unwrap().run_id;
    let projection =
        kuzushi_core::run_lifecycle::load_run_projection(workspace.root(), run).unwrap();
    let summaries = projection.presentation_hydration.verified_summaries();
    assert_eq!(summaries.len(), 1, "{projection:?}");
    assert_eq!(summaries[0].status, status);
}

#[cfg(unix)]
#[test]
fn cargo_audit_missing_lockfile_records_failure_instead_of_clean_scan() {
    let target = tempfile::tempdir().unwrap();
    let adapter = tempfile::tempdir().unwrap();
    let binary = offline_audit_fixture(adapter.path());
    fs::write(
        target.path().join("Cargo.toml"),
        "[package]\nname = \"owned-fixture\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let result = audit_result(
        &mut app,
        &workspace,
        json!({"offline":true,"binary":binary}),
    );
    assert!(
        !adapter.path().join("args").exists(),
        "the scanner must not start without its lockfile"
    );
    assert_eq!(
        kuzushi_core::tool_result_status(&result),
        kuzushi_core::ToolResultStatus::Failed
    );
    assert_recorded_status(&app, &workspace, "failed");
    let output = result["output"].as_str().unwrap();
    assert!(output.contains("regular Cargo.lock"), "{result}");
    assert!(output.contains("No audit started"), "{result}");
    assert!(!output.contains("0 advisory findings"));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("regular Cargo.lock")));
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert!(store.list_all_findings().unwrap().is_empty());
}

#[cfg(unix)]
fn offline_audit_fixture(directory: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let binary = directory.join("owned-audit.sh");
    fs::write(
        &binary,
        r#"#!/bin/sh
set -eu
capture_dir=${0%/*}
printf '%s\n' "$@" > "$capture_dir/args"
pwd -P > "$capture_dir/cwd"
cat > "$capture_dir/stdin"
printf '%s' '{"vulnerabilities":{"found":true,"list":[{"advisory":{"id":"RUSTSEC-OWNED-1","title":"Synthetic owned advisory"},"package":{"name":"owned-fixture","version":"1.0.0"}}]}}'
exit 1
"#,
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    binary
}

#[cfg(unix)]
#[test]
fn run_command_dispatches_cargo_audit_through_registry() {
    let target = tempfile::tempdir().unwrap();
    let adapter = tempfile::tempdir().unwrap();
    let lockfile = "# Synthetic owned dependency metadata; never built\nversion=3\n";
    fs::write(target.path().join("Cargo.lock"), lockfile).unwrap();
    let binary = offline_audit_fixture(adapter.path());
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let result = audit_result(
        &mut app,
        &workspace,
        json!({"binary":binary,"offline":true,"timeoutMs":5000,"maxLockfileBytes":1024}),
    );
    assert_eq!(
        kuzushi_core::tool_result_status(&result),
        kuzushi_core::ToolResultStatus::Completed
    );
    assert_recorded_status(&app, &workspace, "completed");
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert_eq!(
        fs::read_to_string(adapter.path().join("stdin")).unwrap(),
        lockfile
    );
    assert_eq!(
        fs::read_to_string(target.path().join("Cargo.lock")).unwrap(),
        lockfile
    );
    assert_eq!(
        fs::read_to_string(adapter.path().join("args")).unwrap(),
        "audit\n--json\n--file\n-\n--no-fetch\n--no-yanked\n"
    );
    let cwd = fs::read_to_string(adapter.path().join("cwd")).unwrap();
    assert!(!Path::new(cwd.trim()).starts_with(target.path().canonicalize().unwrap()));
    assert_audit_evidence(&result, &workspace);
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "result" && line.body.contains("cargo-audit: 1 advisory findings")
    }));
}

#[cfg(unix)]
fn assert_audit_evidence(result: &Value, workspace: &WorkspaceTarget) {
    assert_eq!(result["data"]["count"], 1);
    assert_eq!(
        result["data"]["coreFindings"][0]["staticProofState"],
        "signal_only"
    );
    let inspection = &result["data"]["nativeInspections"][0];
    assert_eq!(inspection["offline"], true);
    assert_eq!(inspection["configuredLimits"]["timeoutMs"], 5000);
    assert_eq!(inspection["configuredLimits"]["maxLockfileBytes"], 1024);
    assert_eq!(inspection["capturedLockfiles"].as_array().unwrap().len(), 1);
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("Nested lockfiles and source reachability were not inspected"));
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_all_findings().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "cargo-audit");
    let run = result["data"]["persisted"]["runId"].as_str().unwrap();
    assert_eq!(
        store
            .count_finding_observations_for_scan_ids(&[run])
            .unwrap(),
        1
    );
}
