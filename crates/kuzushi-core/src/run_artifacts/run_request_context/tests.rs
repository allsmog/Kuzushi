use super::*;
use serde_json::json;
mod inherited;
mod investigation;

fn publish(root: &Path, input: &Value) {
    write_run_artifact_json(root, "owned-run", "input.json", "tool input", input).unwrap();
}

#[test]
fn recorded_path_selection_is_not_promoted_to_coverage_or_an_allowance() {
    let root = tempfile::tempdir().unwrap();
    publish(root.path(), &json!({"paths":["api","shared"]}));
    let context = load_run_request_context(root.path(), "owned-run").unwrap();
    assert_eq!(
        context.scope.unwrap(),
        RecordedRequestScope::ExplicitPaths { count: 2 }
    );
    assert_eq!(context.allowance.unwrap(), None);
    assert!(!root.path().join(".kuzushi/v3/index.sqlite3").exists());
}

#[test]
fn missing_or_changed_input_cannot_masquerade_as_a_whole_repository_request() {
    let root = tempfile::tempdir().unwrap();
    assert!(load_run_request_context(root.path(), "owned-run").is_err());
    publish(root.path(), &json!({"paths":["api"]}));
    fs::write(
        run_artifact_path(root.path(), "owned-run", "input.json"),
        "{}",
    )
    .unwrap();
    assert!(load_run_request_context(root.path(), "owned-run")
        .unwrap_err()
        .to_string()
        .contains("changed since publication"));
}

#[test]
fn invalid_scope_and_unavailable_ledger_remain_independent_read_errors() {
    let root = tempfile::tempdir().unwrap();
    publish(
        root.path(),
        &json!({"scanScopeRef":{"scopeId":"bad"},"allowanceRef":{
        "schemaVersion":1,"investigationId":"missing","revision":1,"workId":"job"}}),
    );
    let context = load_run_request_context(root.path(), "owned-run").unwrap();
    assert!(context.scope.is_err());
    assert!(context.allowance.is_err());
    assert!(!root.path().join(".kuzushi/v3/index.sqlite3").exists());
}

#[test]
fn absent_scope_and_explicit_omission_do_not_invent_discovery_membership() {
    let root = tempfile::tempdir().unwrap();
    publish(root.path(), &json!({"scanScopeRef":null}));
    assert_eq!(
        load_run_request_context(root.path(), "owned-run")
            .unwrap()
            .scope
            .unwrap(),
        RecordedRequestScope::NotRecorded
    );
}

#[test]
fn scope_only_reads_do_not_depend_on_unavailable_allowance_state() {
    let root = tempfile::tempdir().unwrap();
    publish(
        root.path(),
        &json!({"scanScopeRef":null,"allowanceRef":{"schemaVersion":999}}),
    );
    assert!(load_run_request_context(root.path(), "owned-run")
        .unwrap()
        .allowance
        .is_err());
    assert_eq!(
        load_run_request_scope(root.path(), "owned-run").unwrap(),
        RecordedRequestScope::NotRecorded
    );
    assert!(!root.path().join(".kuzushi/v3/index.sqlite3").exists());
}

fn accepted_scope(workspace: &WorkspaceTarget) -> ScanScopeRef {
    use crate::workspace::{
        accept_scan_scope_proposal, create_scan_scope_proposal, ScopeCoverageApproval,
    };
    let config = crate::V2Config::default();
    let ctx = crate::ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let draft = create_scan_scope_proposal(&ctx, None).unwrap();
    let accepted = accept_scan_scope_proposal(
        &ctx,
        &draft.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            ..Default::default()
        },
    )
    .unwrap();
    ScanScopeRef {
        proposal: accepted.reference,
        scope_id: "repository".into(),
    }
}

#[test]
fn historical_accepted_scope_remains_readable_after_source_drift() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("lib.rs"), "pub fn before() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let reference = accepted_scope(&workspace);
    publish(root.path(), &json!({"scanScopeRef":reference}));
    let before = load_run_request_context(root.path(), "owned-run").unwrap();
    fs::write(root.path().join("lib.rs"), "pub fn after() {}\n").unwrap();
    let after = load_run_request_context(root.path(), "owned-run").unwrap();
    assert_eq!(before.scope, after.scope);
    assert!(
        matches!(after.scope, Ok(RecordedRequestScope::Accepted {reference: r, ..}) if r == reference)
    );
    assert!(!workspace.state_dir().join("campaigns").exists());
}

#[test]
fn absent_scope_id_and_malformed_path_selection_are_honest_errors() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("lib.rs"), "pub fn source() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut reference = accepted_scope(&workspace);
    reference.scope_id = "missing".into();
    publish(root.path(), &json!({"scanScopeRef":reference}));
    assert!(load_run_request_context(root.path(), "owned-run")
        .unwrap()
        .scope
        .is_err());
    let malformed = tempfile::tempdir().unwrap();
    publish(malformed.path(), &json!({"paths":"lib.rs"}));
    assert!(load_run_request_context(malformed.path(), "owned-run")
        .unwrap()
        .scope
        .is_err());
}
