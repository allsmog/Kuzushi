//! Child discovery keeps workspace paths, identities and retained source aligned.
use crate::run_artifacts::{record_tool_run_started, ToolRunRecord, TraceHandle};
use crate::{FindingStore, ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::fs;

const PARENT: &str = "{\"name\":\"parent\",\"license\":\"MIT\"}\n";
const CHILD: &str = "{\"name\":\"owned-child\",\"dependencies\":{\"owned-example\":\"*\"}}\n";
const CHILD_SECRET: &str = "# Owned child documentation example. Never executed.\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n";

fn fixture() -> (tempfile::TempDir, WorkspaceTarget, FindingStore) {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("package.json"), PARENT).unwrap();
    fs::write(root.path().join("LICENSE"), "Owned inert text.\n").unwrap();
    for name in ["client", "service"] {
        fs::create_dir(root.path().join(name)).unwrap();
        fs::write(root.path().join(name).join("package.json"), CHILD).unwrap();
    }
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    (root, workspace, store)
}

fn dispatch(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    tool: &str,
    run: &str,
    input: Value,
) -> Value {
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let trace = (tool != "sast:scan").then(|| TraceHandle::jsonl(workspace.root(), run));
    if trace.is_some() {
        record_tool_run_started(
            ToolRunRecord::new(workspace.root(), run, "tool", tool),
            &input,
        );
    }
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: trace.as_ref(),
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input(tool, input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let output = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(output["status"], "completed", "{output:#}");
    output
}

fn assert_saved_sources(store: &FindingStore, expected_paths: &[&str]) {
    let mut findings = store.list_all_findings().unwrap();
    findings.sort_by(|left, right| left.file_path.cmp(&right.file_path));
    assert_eq!(
        findings
            .iter()
            .map(|finding| finding.file_path.as_str())
            .collect::<Vec<_>>(),
        expected_paths
    );
    for finding in findings {
        let source = store
            .recorded_observation_source(finding.id.unwrap())
            .unwrap()
            .unwrap();
        let bytes = store
            .read_observation_blob(source.blob_hash.as_ref().unwrap())
            .unwrap()
            .unwrap();
        let expected = if finding.tool == "secret-scan" {
            CHILD_SECRET
        } else {
            CHILD
        };
        assert_eq!(
            bytes,
            expected.as_bytes(),
            "{} must retain its own source",
            finding.file_path
        );
        assert_ne!(bytes, PARENT.as_bytes());
    }
}

fn assert_child(tool: &str) {
    let (_root, workspace, store) = fixture();
    let output = dispatch(
        &workspace,
        &store,
        tool,
        "child",
        json!({"target":workspace.root().join("client")}),
    );
    assert_eq!(
        output["data"]["coreFindings"][0]["file_path"],
        "client/package.json"
    );
    assert_saved_sources(&store, &["client/package.json"]);
}

#[test]
fn license_child_target_keeps_workspace_path_and_actual_source() {
    assert_child("license-scan:scan");
}

#[test]
fn dependency_child_target_keeps_workspace_path_and_actual_source() {
    assert_child("dep-hygiene:check");
}

fn assert_siblings(tool: &str) {
    let (_root, workspace, store) = fixture();
    for name in ["client", "service"] {
        dispatch(
            &workspace,
            &store,
            tool,
            name,
            json!({"target":workspace.root().join(name)}),
        );
    }
    assert_saved_sources(&store, &["client/package.json", "service/package.json"]);
}

#[test]
fn sibling_license_targets_do_not_collapse_one_another() {
    assert_siblings("license-scan:scan");
}

#[test]
fn sibling_dependency_targets_do_not_collapse_one_another() {
    assert_siblings("dep-hygiene:check");
}

fn assert_direct_and_sast(tool: &str, engine: &str) {
    let (_root, workspace, store) = fixture();
    let direct = dispatch(
        &workspace,
        &store,
        tool,
        "direct",
        json!({"target":workspace.root().join("client")}),
    );
    let sast = dispatch(
        &workspace,
        &store,
        "sast:scan",
        "sast",
        json!({
            "taskMode":"manual","tasks":[engine],"paths":["client"],
            "triage":false,"verify":false,"autoPatch":false,
        }),
    );
    assert_eq!(
        direct["data"]["coreFindings"][0]["fingerprint"],
        sast["data"]["coreFindings"][0]["fingerprint"]
    );
    assert_saved_sources(&store, &["client/package.json"]);
}

#[test]
fn license_direct_child_and_sast_directory_keep_the_same_identity() {
    assert_direct_and_sast("license-scan:scan", "license-scan");
}

#[test]
fn dependency_direct_child_and_sast_directory_keep_the_same_identity() {
    assert_direct_and_sast("dep-hygiene:check", "dep-hygiene");
}

fn secret_fixture() -> (tempfile::TempDir, WorkspaceTarget, FindingStore) {
    let (root, workspace, store) = fixture();
    fs::write(
        root.path().join("config.env"),
        "# Owned parent documentation example.\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();
    for name in ["client", "service"] {
        fs::write(root.path().join(name).join("config.env"), CHILD_SECRET).unwrap();
    }
    (root, workspace, store)
}

#[test]
fn secret_child_target_keeps_workspace_path_and_actual_source() {
    let (_root, workspace, store) = secret_fixture();
    let output = dispatch(
        &workspace,
        &store,
        "secret-scan:scan",
        "secret-child",
        json!({"target":workspace.root().join("client")}),
    );
    assert_eq!(
        output["data"]["coreFindings"][0]["file_path"],
        "client/config.env"
    );
    assert_saved_sources(&store, &["client/config.env"]);
}

#[test]
fn sibling_secret_targets_do_not_collapse_one_another() {
    let (_root, workspace, store) = secret_fixture();
    for name in ["client", "service"] {
        dispatch(
            &workspace,
            &store,
            "secret-scan:scan",
            name,
            json!({"target":workspace.root().join(name)}),
        );
    }
    assert_saved_sources(&store, &["client/config.env", "service/config.env"]);
}

#[test]
fn secret_direct_child_and_sast_directory_keep_one_identity_and_legacy_aliases() {
    let (_root, workspace, store) = secret_fixture();
    let direct = dispatch(
        &workspace,
        &store,
        "secret-scan:scan",
        "direct-secret",
        json!({"target":workspace.root().join("client")}),
    );
    let legacy = crate::secret_scan::scan_for_secrets(
        &workspace.root().join("client"),
        &Default::default(),
        &Default::default(),
    )
    .unwrap();
    assert_eq!(
        direct["data"]["coreFindings"][0]["fingerprint"],
        legacy.findings[0].fingerprint
    );
    dispatch(
        &workspace,
        &store,
        "sast:scan",
        "sast-secret",
        json!({
            "taskMode":"manual","tasks":["secret-scan"],"paths":["client"],
            "triage":false,"verify":false,"autoPatch":false,
        }),
    );
    assert_saved_sources(&store, &["client/config.env"]);
}

#[cfg(unix)]
fn assert_literal_child(tool: &str) {
    let (_root, workspace, store) = fixture();
    let name = "client\\scope";
    fs::rename(workspace.root().join("client"), workspace.root().join(name)).unwrap();
    let output = dispatch(
        &workspace,
        &store,
        tool,
        "literal-child",
        json!({"target":workspace.root().join(name)}),
    );
    assert_eq!(
        output["data"]["coreFindings"][0]["file_path"],
        "client\\scope/package.json"
    );
    assert_saved_sources(&store, &["client\\scope/package.json"]);
}

#[cfg(unix)]
#[test]
fn license_child_target_preserves_a_literal_unix_backslash() {
    assert_literal_child("license-scan:scan");
}

#[cfg(unix)]
#[test]
fn dependency_child_target_preserves_a_literal_unix_backslash() {
    assert_literal_child("dep-hygiene:check");
}

fn assert_child_workflow_source(tool: &str) {
    let (_root, workspace, store) = secret_fixture();
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let record = ToolRunRecord::new(workspace.root(), "child-source", "tool", tool);
    record_tool_run_started(record, &json!({"target":"client"}));
    let trace = TraceHandle::jsonl(workspace.root(), "child-source");
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: Some(&trace),
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input(tool, json!({"target":"client"}), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let observed = registry
        .dispatch_prepared_input_observed_with_runtime(prepared, &ctx, None)
        .unwrap();
    let output = observed.execution.unwrap();
    assert_eq!(output["status"], "completed");
    crate::run_artifacts::try_record_tool_run_complete_settled(
        record,
        &output,
        &trace.run_observation().unwrap(),
        observed.completion,
    )
    .unwrap();
    let identity = crate::workflow_attempts::referenced_run_content_identity(
        workspace.root(),
        &["child-source".into()],
    );
    assert!(
        matches!(
            identity,
            crate::workflow_attempts::TargetContentIdentity::IndexedSnapshot { .. }
        ),
        "{tool}: {identity:?}"
    );
    assert!(
        crate::workflow_attempts::referenced_runs_match_current_source(
            workspace.root(),
            &["child-source".into()]
        )
    );
    assert!(!workspace.root().join("client/.kuzushi").exists());
}

#[test]
fn child_license_workflow_identity_is_owned_by_parent_workspace() {
    assert_child_workflow_source("license-scan:scan");
}

#[test]
fn child_dependency_workflow_identity_is_owned_by_parent_workspace() {
    assert_child_workflow_source("dep-hygiene:check");
}

#[test]
fn child_secret_workflow_identity_is_owned_by_parent_workspace() {
    assert_child_workflow_source("secret-scan:scan");
}
