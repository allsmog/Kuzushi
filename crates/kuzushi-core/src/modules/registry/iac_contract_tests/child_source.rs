//! Exact prepared dispatch must preserve child source and literal path membership.
use super::*;
use crate::run_artifacts::{record_tool_run_started, ToolRunRecord, TraceHandle};
use std::path::Path;

const PARENT: &str = "FROM owned:1.0\nUSER nobody\n# Owned parent, never built.\n";
const CHILD: &str = "FROM owned:latest\nUSER nobody\n# Owned child, never built.\n";
const LITERAL: &str = "FROM owned:latest\nUSER nobody\n# Owned literal directory, never built.\n";

fn fixture(children: &[(&str, &str)]) -> (tempfile::TempDir, WorkspaceTarget, FindingStore) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("Dockerfile"), PARENT).unwrap();
    for (path, text) in children {
        std::fs::create_dir_all(root.path().join(path)).unwrap();
        std::fs::write(root.path().join(path).join("Dockerfile"), text).unwrap();
    }
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    (root, workspace, store)
}

fn observed(workspace: &WorkspaceTarget, store: &FindingStore, run: &str, target: &str) -> Value {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let config = V2Config::default();
    let input = json!({"target":target});
    let record = ToolRunRecord::new(workspace.root(), run, "tool", "iac-scan:scan");
    record_tool_run_started(record, &input);
    let trace = TraceHandle::jsonl(workspace.root(), run);
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: Some(&trace),
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input("iac-scan:scan", input, &ctx, None)
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
    let coverage = crate::run_artifacts::load_scan_stage_data(workspace.root(), run)
        .unwrap()
        .expect("Published direct IaC coverage must remain readable");
    assert_eq!(
        serde_json::to_value(coverage).unwrap(),
        output["data"]["phaseStages"][0]
    );
    output
}

fn assert_source(store: &FindingStore, path: &str, expected: &str) {
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
    assert_eq!(bytes, expected.as_bytes(), "{path}");
    assert_ne!(bytes, PARENT.as_bytes());
}

#[test]
fn iac_child_workflow_identity_is_owned_by_the_parent_workspace() {
    let (_root, workspace, store) = fixture(&[("client", CHILD)]);
    observed(&workspace, &store, "child-source", "client");
    assert_source(&store, "client/Dockerfile", CHILD);
    let identity = crate::workflow_attempts::referenced_run_content_identity(
        workspace.root(),
        &["child-source".into()],
    );
    assert!(
        matches!(
            identity,
            crate::workflow_attempts::TargetContentIdentity::IndexedSnapshot { .. }
        ),
        "{identity:?}"
    );
    assert!(
        crate::workflow_attempts::referenced_runs_match_current_source(
            workspace.root(),
            &["child-source".into()]
        )
    );
    assert!(!workspace.root().join("client/.kuzushi").exists());
}

#[cfg(unix)]
#[test]
fn literal_iac_child_and_real_nested_paths_keep_separate_source_and_coverage() {
    let (_root, workspace, store) = fixture(&[("client\\scope", LITERAL), ("client/scope", CHILD)]);
    let literal = observed(&workspace, &store, "literal-child", "client\\scope");
    let normal = observed(&workspace, &store, "nested-child", "client/scope");
    assert_eq!(
        literal["data"]["coreFindings"][0]["file_path"],
        "client\\scope/Dockerfile"
    );
    assert_eq!(
        literal["data"]["inspectedFiles"],
        json!(["client\\scope/Dockerfile"])
    );
    assert_eq!(
        literal["data"]["phaseStages"][0]["scan"]["scope"]["paths"],
        json!(["client\\scope"])
    );
    assert_ne!(
        literal["data"]["coreFindings"][0]["fingerprint"],
        normal["data"]["coreFindings"][0]["fingerprint"]
    );
    assert_eq!(store.list_all_findings().unwrap().len(), 2);
    assert_source(&store, "client\\scope/Dockerfile", LITERAL);
    assert_source(&store, "client/scope/Dockerfile", CHILD);
}

#[cfg(unix)]
#[test]
fn literal_iac_direct_and_sast_keep_one_identity_for_the_same_child() {
    let (_root, workspace, store) = fixture(&[("client\\scope", LITERAL)]);
    let direct = observed(&workspace, &store, "literal-direct", "client\\scope");
    let sast = dispatch_named(
        &workspace,
        "sast:scan",
        json!({"taskMode":"manual","tasks":["iac-scan"],
        "paths":["client\\scope"],"triage":false,"verify":false,"autoPatch":false}),
    );
    assert_eq!(sast["status"], "completed", "{sast:#}");
    assert_eq!(sast["data"]["findingsCount"], 1);
    let findings = store.list_all_findings().unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].file_path, "client\\scope/Dockerfile");
    assert_eq!(
        findings[0].fingerprint,
        direct["data"]["coreFindings"][0]["fingerprint"]
    );
    assert_source(&store, "client\\scope/Dockerfile", LITERAL);
}

#[cfg(unix)]
#[test]
fn iac_root_inventory_preserves_both_literal_and_nested_inspected_members() {
    let (_root, workspace, _store) =
        fixture(&[("client\\scope", LITERAL), ("client/scope", CHILD)]);
    let report =
        crate::iac_scan::scan_iac(workspace.root(), &Default::default(), &Default::default())
            .unwrap();
    assert_eq!(
        report.inspected_files.unwrap(),
        [
            "Dockerfile",
            "client/scope/Dockerfile",
            "client\\scope/Dockerfile"
        ]
        .map(str::to_owned)
        .into_iter()
        .collect()
    );
    assert_eq!(
        crate::workspace::inventory::repo_relative(
            workspace.root(),
            &workspace.root().join(Path::new("client\\scope/Dockerfile"))
        ),
        "client\\scope/Dockerfile"
    );
}
