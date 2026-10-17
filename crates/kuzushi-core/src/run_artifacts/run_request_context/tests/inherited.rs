use super::*;
use crate::allowance::{AllowanceApprovalV1, AllowanceCall, AllowanceLimits, AllowanceWork};
use crate::runtime::RuntimeCostReport;
use crate::SpendLimiter;

fn approval(revision: u32, max: u32) -> AllowanceApprovalV1 {
    AllowanceApprovalV1 {
        schema_version: 1,
        investigation_id: "owned-study".into(),
        expected_revision: revision,
        model: "selected:model".into(),
        limits: AllowanceLimits {
            max_provider_calls: max,
            protected_review_calls: 1,
        },
        reason: "Owned accounting-only fixture. No provider request.".into(),
        work_plan: None,
    }
}

fn work() -> AllowanceWork {
    AllowanceWork {
        investigation_id: "owned-study".into(),
        revision: 1,
        run_id: "parent".into(),
        work_id: "parent-review".into(),
        model: "selected:model".into(),
        work: InvestigationWork::Review,
    }
}

fn retain(root: &Path, work: &AllowanceWork) {
    publish(root, &json!({"paths":["api"]}));
    crate::run_artifacts::retain_inherited_allowance(root, "owned-run", work).unwrap();
}

fn ledger(workspace: &WorkspaceTarget) -> SpendLimiter {
    workspace.ensure_state_dir().unwrap();
    let ledger = SpendLimiter::open(&workspace.findings_db_path()).unwrap();
    ledger.approve_allowance(&approval(0, 3)).unwrap();
    ledger
}

fn charge_parent(ledger: &SpendLimiter) {
    let reserved = ledger
        .reserve_provider_call(&AllowanceCall {
            investigation_id: "owned-study".into(),
            expected_revision: 1,
            request_id: "owned-request".into(),
            run_id: "parent".into(),
            work_id: "parent-review".into(),
            model: "selected:model".into(),
            work: InvestigationWork::Review,
        })
        .unwrap();
    ledger
        .settle_provider_call(reserved, RuntimeCostReport::UNAVAILABLE)
        .unwrap();
}

#[test]
fn inherited_parent_totals_and_original_grant_survive_a_later_revision() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let ledger = ledger(&workspace);
    retain(root.path(), &work());
    charge_parent(&ledger);
    ledger.approve_allowance(&approval(1, 5)).unwrap();
    let read = load_run_request_context(root.path(), "owned-run").unwrap();
    assert_eq!(
        read.allowance_origin,
        RecordedAllowanceOrigin::Inherited {
            accounting_run_id: "parent".into(),
            work: InvestigationWork::Review,
        }
    );
    let context = read.allowance.unwrap().unwrap();
    assert_eq!(context.approved_limits.max_provider_calls, 3);
    assert_eq!(context.reference.revision, 1);
    assert_eq!(context.current.revision, 2);
    assert_eq!(context.current.limits.max_provider_calls, 5);
    assert_eq!(
        (context.run_committed_calls, context.run_unsettled_calls),
        (1, 0)
    );
    assert_eq!(context.current.cost, RuntimeCostReport::UNAVAILABLE);
}

#[test]
fn explicit_and_inherited_conflicts_are_errors_without_losing_scope() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let _ledger = ledger(&workspace);
    retain(root.path(), &work());
    publish(
        root.path(),
        &json!({"paths":["api"],"allowanceRef":{
        "schemaVersion":1,"investigationId":"owned-study","revision":1,"workId":"other"}}),
    );
    let read = load_run_request_context(root.path(), "owned-run").unwrap();
    assert!(read
        .allowance
        .unwrap_err()
        .contains("explicit and inherited accounting differ"));
    assert_eq!(read.allowance_origin, RecordedAllowanceOrigin::Unavailable);
    assert_eq!(
        read.scope.unwrap(),
        RecordedRequestScope::ExplicitPaths { count: 1 }
    );
}

#[test]
fn matching_explicit_reference_keeps_its_original_origin() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let _ledger = ledger(&workspace);
    let mut same = work();
    same.run_id = "owned-run".into();
    retain(root.path(), &same);
    publish(
        root.path(),
        &json!({"allowanceRef":{
        "schemaVersion":1,"investigationId":"owned-study","revision":1,"workId":"parent-review"}}),
    );
    let read = load_run_request_context(root.path(), "owned-run").unwrap();
    assert_eq!(read.allowance_origin, RecordedAllowanceOrigin::Explicit);
    assert!(read.allowance.unwrap().is_some());
}

#[test]
fn missing_ledger_and_damaged_retention_are_independent_read_errors() {
    let root = tempfile::tempdir().unwrap();
    retain(root.path(), &work());
    let read = load_run_request_context(root.path(), "owned-run").unwrap();
    assert!(read
        .allowance
        .unwrap_err()
        .contains("ledger is unavailable"));
    assert_eq!(read.allowance_origin, RecordedAllowanceOrigin::Unavailable);
    assert!(!root.path().join(".kuzushi/v3/index.sqlite3").exists());
    let artifact = run_artifact_path(root.path(), "owned-run", "inherited-allowance.json");
    fs::write(&artifact, "{}").unwrap();
    let read = load_run_request_context(root.path(), "owned-run").unwrap();
    assert!(read
        .allowance
        .unwrap_err()
        .contains("changed since retention"));
    assert!(read.scope.is_ok());
    fs::remove_file(artifact).unwrap();
    let read = load_run_request_context(root.path(), "owned-run").unwrap();
    assert!(read
        .allowance
        .unwrap_err()
        .contains("missing after retention"));
}
