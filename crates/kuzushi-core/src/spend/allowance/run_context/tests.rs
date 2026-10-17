use super::*;

fn approval() -> AllowanceApprovalV1 {
    AllowanceApprovalV1 {
        schema_version: 1,
        investigation_id: "owned".into(),
        expected_revision: 0,
        model: "operator:model".into(),
        limits: AllowanceLimits {
            max_provider_calls: 3,
            protected_review_calls: 1,
        },
        reason: "Owned offline accounting only".into(),
        work_plan: None,
    }
}

fn reference() -> AllowanceReferenceV1 {
    AllowanceReferenceV1 {
        schema_version: 1,
        investigation_id: "owned".into(),
        revision: 1,
        work_id: "job".into(),
    }
}

fn reserve(ledger: &SpendLimiter, id: &str) -> AllowanceReservation {
    ledger
        .reserve_provider_call(&AllowanceCall {
            investigation_id: "owned".into(),
            expected_revision: 1,
            request_id: id.into(),
            run_id: "run".into(),
            work_id: "job".into(),
            model: "operator:model".into(),
            work: InvestigationWork::Discovery,
        })
        .unwrap()
}

#[test]
fn historical_grant_stays_distinct_from_revised_current_limits_and_unknown_cost() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ledger.db");
    let ledger = SpendLimiter::open(&path).unwrap();
    ledger.approve_allowance(&approval()).unwrap();
    ledger
        .settle_provider_call(
            reserve(&ledger, "refused"),
            crate::runtime::RuntimeCostReport::UNAVAILABLE,
        )
        .unwrap();
    drop(reserve(&ledger, "interrupted"));
    let mut next = approval();
    next.expected_revision = 1;
    next.limits.max_provider_calls = 7;
    next.model = "operator:explicit-new-model".into();
    ledger.approve_allowance(&next).unwrap();
    let before = ledger.allowance_snapshot("owned").unwrap();
    let read = SpendLimiter::read_run_allowance_context(&path, "run", &reference()).unwrap();
    assert_eq!(read.approved_limits.max_provider_calls, 3);
    assert_eq!(read.approved_model, "operator:model");
    assert_eq!(read.current.revision, 2);
    assert_eq!(read.current.limits.max_provider_calls, 7);
    assert_eq!((read.run_committed_calls, read.run_unsettled_calls), (2, 1));
    assert_eq!(read.current.protected_review_remaining(), 1);
    assert_eq!(read.current.cost.exact_usd(), None);
    assert_eq!(ledger.allowance_snapshot("owned").unwrap(), before);
}

#[test]
fn zero_is_only_shown_after_a_real_grant_and_missing_ledgers_are_not_created() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ledger.db");
    assert!(SpendLimiter::read_run_allowance_context(&path, "run", &reference()).is_err());
    assert!(!path.exists());
    let ledger = SpendLimiter::open(&path).unwrap();
    ledger.approve_allowance(&approval()).unwrap();
    let read = SpendLimiter::read_run_allowance_context(&path, "run", &reference()).unwrap();
    assert_eq!(read.run_committed_calls, 0);
    assert_eq!(read.current.committed_calls, 0);
    assert!(SpendLimiter::read_run_provider_usage(&path, "run")
        .unwrap()
        .is_none());
}

#[test]
fn other_work_and_malformed_historical_approvals_are_never_borrowed() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ledger.db");
    let ledger = SpendLimiter::open(&path).unwrap();
    ledger.approve_allowance(&approval()).unwrap();
    drop(reserve(&ledger, "one"));
    let mut wrong = reference();
    wrong.work_id = "another-job".into();
    assert!(SpendLimiter::read_run_allowance_context(&path, "run", &wrong).is_err());
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "update investigation_allowance_revisions set approval_json='{}'",
        [],
    )
    .unwrap();
    assert!(SpendLimiter::read_run_allowance_context(&path, "run", &reference()).is_err());
}
