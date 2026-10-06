use super::*;
use crate::allowance::{AllowanceCall, InvestigationWork};
use crate::runtime::RuntimeCostReport;
use crate::spend::allowance::work_tests::{approval, claim, reference};

fn fixture() -> (tempfile::TempDir, SpendLimiter) {
    let root = tempfile::tempdir().unwrap();
    let ledger = SpendLimiter::open(root.path().join("ledger.db")).unwrap();
    ledger.approve_allowance(&approval()).unwrap();
    claim(&ledger, &reference(), "scan-one").unwrap();
    (root, ledger)
}

fn reserve(ledger: &SpendLimiter, id: &str) -> super::super::AllowanceReservation {
    ledger
        .reserve_provider_call(&AllowanceCall {
            investigation_id: "study".into(),
            expected_revision: 1,
            request_id: id.into(),
            run_id: "scan-one".into(),
            work_id: reference().work_id,
            model: approval().model,
            work: InvestigationWork::Discovery,
        })
        .unwrap()
}

fn read(root: &Path) -> Option<ProviderRunUsage> {
    SpendLimiter::read_run_provider_usage(&root.join("ledger.db"), "scan-one").unwrap()
}

#[test]
fn counts_all_internal_attempts_even_when_dollar_cost_is_unknown() {
    let (root, ledger) = fixture();
    for n in 1..=4 {
        let reservation = reserve(&ledger, &format!("request-{n}"));
        ledger
            .settle_provider_call(reservation, RuntimeCostReport::UNAVAILABLE)
            .unwrap();
    }
    let before = ledger.allowance_snapshot("study").unwrap();
    let observed = read(root.path()).unwrap();
    assert_eq!(
        (observed.committed_calls, observed.unresolved_calls),
        (4, 0)
    );
    assert_eq!(observed.tool, "sast:scan");
    assert_eq!(observed.model, approval().model);
    assert!(before.cost.is_unavailable());
    assert_eq!(before, ledger.allowance_snapshot("study").unwrap());
    let mut revised = approval();
    revised.expected_revision = 1;
    revised.model = "operator:other-model".into();
    ledger.approve_allowance(&revised).unwrap();
    assert_eq!(read(root.path()).unwrap(), observed);
}

#[test]
fn unresolved_calls_stay_committed_and_an_admitted_zero_differs_from_missing_evidence() {
    let (root, ledger) = fixture();
    assert_eq!(read(root.path()).unwrap().committed_calls, 0);
    let _unresolved = reserve(&ledger, "cancelled-transport");
    assert_eq!(
        (
            read(root.path()).unwrap().committed_calls,
            read(root.path()).unwrap().unresolved_calls
        ),
        (1, 1)
    );
    assert!(
        SpendLimiter::read_run_provider_usage(&root.path().join("ledger.db"), "not-admitted")
            .unwrap()
            .is_none()
    );
}

#[test]
fn missing_or_legacy_ledgers_are_not_created_migrated_or_reported_as_zero() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ledger.db");
    assert!(SpendLimiter::read_run_provider_usage(&path, "run")
        .unwrap()
        .is_none());
    assert!(!path.exists());
    Connection::open(&path)
        .unwrap()
        .execute("create table legacy(value text)", [])
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(SpendLimiter::read_run_provider_usage(&path, "run")
        .unwrap()
        .is_none());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(SpendLimiter::read_run_provider_usage(&path, "../run").is_err());
}

#[test]
fn changed_call_identity_or_work_receipt_refuses_calibration() {
    for damage in ["model", "workId", "work", "source"] {
        let (root, ledger) = fixture();
        let _reservation = reserve(&ledger, "request");
        let state = ledger.lock();
        if damage == "source" {
            state.conn.execute("update investigation_work_attempts set job_json=json_set(job_json,'$.source_identity','other-source')", []).unwrap();
        } else {
            state.conn.execute("update investigation_call_reservations set call_json=json_set(call_json,?,'foreign')", [format!("$.{damage}")]).unwrap();
        }
        drop(state);
        assert!(
            SpendLimiter::read_run_provider_usage(&root.path().join("ledger.db"), "scan-one")
                .is_err(),
            "{damage}"
        );
    }
}

#[test]
fn ambiguous_run_ownership_is_not_an_estimate() {
    let (root, ledger) = fixture();
    let mut second = approval();
    second.investigation_id = "second".into();
    second.work_plan.as_mut().unwrap().campaign_id = "second-batch".into();
    ledger.approve_allowance(&second).unwrap();
    let mut reference = reference();
    reference.investigation_id = "second".into();
    claim(&ledger, &reference, "scan-one").unwrap();
    assert!(
        SpendLimiter::read_run_provider_usage(&root.path().join("ledger.db"), "scan-one").is_err()
    );
}

#[test]
fn shared_status_dispatch_reports_requests_without_spending_or_changing_approval() {
    use crate::{
        modules::{ModuleRegistry, ToolExecutionContext},
        V2Config, WorkspaceTarget,
    };
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let ledger = SpendLimiter::open(workspace.findings_db_path()).unwrap();
    ledger.approve_allowance(&approval()).unwrap();
    claim(&ledger, &reference(), "scan-one").unwrap();
    for n in 1..=4 {
        let reservation = reserve(&ledger, &format!("request-{n}"));
        ledger
            .settle_provider_call(reservation, RuntimeCostReport::UNAVAILABLE)
            .unwrap();
    }
    let before = ledger.allowance_snapshot("study").unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let input = serde_json::json!({"investigationId":"study","run_id":"scan-one"});
    let prepared = registry
        .prepare_dispatch_input("campaign:allowance", input, &ctx, None)
        .unwrap();
    let output = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(output["data"]["runUsage"]["committedCalls"], 4);
    assert_eq!(output["data"]["runUsage"]["unresolvedCalls"], 0);
    assert_eq!(before, ledger.allowance_snapshot("study").unwrap());
}
