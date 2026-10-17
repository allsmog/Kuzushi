use super::*;
use crate::allowance::{AllowanceApprovalV1, AllowanceCall, AllowanceLimits, InvestigationWork};
use crate::SpendLimiter;

fn approve(ledger: &SpendLimiter, id: &str, revision: u32, max: u32) {
    ledger
        .approve_allowance(&AllowanceApprovalV1 {
            schema_version: 1,
            investigation_id: id.into(),
            expected_revision: revision,
            model: "operator:model".into(),
            limits: AllowanceLimits {
                max_provider_calls: max,
                protected_review_calls: 2,
            },
            reason: "Owned accounting-only read fixture".into(),
            work_plan: None,
        })
        .unwrap();
}

fn publish_named(root: &Path, run: &str, id: &str) {
    write_run_artifact_json(
        root,
        run,
        "input.json",
        "tool input",
        &json!({
            "allowanceRef": {"schemaVersion":1,"investigationId":id,"revision":1,"workId":"job"},
            "scanScopeRef": {"intentionallyInvalid":"not read by accounting"}
        }),
    )
    .unwrap();
}

#[test]
fn investigation_read_follows_recorded_binding_across_revision_and_restart_without_writing() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    workspace.ensure_state_dir().unwrap();
    let ledger = SpendLimiter::open(&workspace.findings_db_path()).unwrap();
    approve(&ledger, "owned", 0, 6);
    publish_named(root.path(), "first", "owned");
    publish_named(root.path(), "second", "owned");
    let reservation = ledger
        .reserve_provider_call(&AllowanceCall {
            investigation_id: "owned".into(),
            expected_revision: 1,
            request_id: "unsettled".into(),
            run_id: "first".into(),
            work_id: "job".into(),
            model: "operator:model".into(),
            work: InvestigationWork::Discovery,
        })
        .unwrap();
    drop(reservation);
    approve(&ledger, "owned", 1, 7);
    let expected = ledger.allowance_snapshot("owned").unwrap();
    drop(ledger);
    let read =
        load_investigation_allowance_for_runs(root.path(), &["first".into(), "second".into()])
            .unwrap()
            .unwrap();
    assert_eq!(read, expected);
    assert_eq!((read.committed_calls, read.unresolved_calls), (1, 1));
    assert_eq!(read.protected_review_remaining(), 2);
    assert_eq!(read.cost.exact_usd(), None);
    assert_eq!(
        SpendLimiter::read_allowance_snapshot(&workspace.findings_db_path(), "owned").unwrap(),
        expected
    );
}

#[test]
fn investigation_read_rejects_conflicting_or_damaged_bindings() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    workspace.ensure_state_dir().unwrap();
    let ledger = SpendLimiter::open(&workspace.findings_db_path()).unwrap();
    for id in ["one", "two"] {
        approve(&ledger, id, 0, 6);
    }
    publish_named(root.path(), "first", "one");
    publish_named(root.path(), "second", "two");
    assert!(
        load_investigation_allowance_for_runs(root.path(), &["first".into(), "second".into()])
            .unwrap_err()
            .to_string()
            .contains("multiple investigation allowances")
    );
    fs::write(run_artifact_path(root.path(), "first", "input.json"), "{}").unwrap();
    assert!(load_investigation_allowance_for_runs(root.path(), &["first".into()]).is_err());
}

#[test]
fn missing_ledger_or_request_is_unavailable_while_unrecorded_grants_stay_absent() {
    let root = tempfile::tempdir().unwrap();
    publish(root.path(), &json!({}));
    assert_eq!(
        load_investigation_allowance_for_runs(root.path(), &["owned-run".into()]).unwrap(),
        None
    );
    publish_named(root.path(), "bound", "missing");
    assert!(load_investigation_allowance_for_runs(root.path(), &["bound".into()]).is_err());
    assert!(load_investigation_allowance_for_runs(root.path(), &["absent".into()]).is_err());
    assert!(!WorkspaceTarget::new(root.path())
        .unwrap()
        .findings_db_path()
        .exists());
}
