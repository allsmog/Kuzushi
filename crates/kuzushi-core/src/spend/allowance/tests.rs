use super::*;
use crate::{runtime::{RuntimeCost, RuntimeCostReport}, spend::SpendLimiter};

fn approval(calls: u32, review: u32) -> AllowanceApprovalV1 {
    AllowanceApprovalV1 {
        schema_version: 1, investigation_id: "study-one".into(), expected_revision: 0,
        model: "openai-codex:gpt-5.5".into(),
        limits: AllowanceLimits { max_provider_calls: calls, protected_review_calls: review },
        reason: "Offline test allowance; no live model requests".into(),
        work_plan: None,
    }
}

fn call(request_id: &str, work: InvestigationWork) -> AllowanceCall {
    AllowanceCall {
        investigation_id: "study-one".into(), expected_revision: 1,
        request_id: request_id.into(), run_id: "run-one".into(), work_id: "context-one".into(),
        model: "openai-codex:gpt-5.5".into(), work,
    }
}

fn fresh(calls: u32, review: u32) -> SpendLimiter {
    let ledger = SpendLimiter::open_in_memory().unwrap();
    ledger.approve_allowance(&approval(calls, review)).unwrap();
    ledger
}

fn known_cost(dollars: f64) -> RuntimeCostReport {
    RuntimeCostReport::known(RuntimeCost::from_usd(dollars, "test cost").unwrap())
}

fn bound_work(revision: u32) -> AllowanceWork {
    AllowanceWork {
        investigation_id: "study-one".into(), revision,
        run_id: "run-one".into(), work_id: "context-one".into(),
        model: "openai-codex:gpt-5.5".into(), work: InvestigationWork::Context,
    }
}

#[test]
fn binding_preserves_host_attribution_and_requires_fresh_revision() {
    let ledger = std::sync::Arc::new(fresh(3, 1));
    let binding = AllowanceBinding::new(ledger.clone(), bound_work(1)).unwrap();
    assert!(binding.reserve("openai-codex:another-model").is_err());
    let first = binding.reserve("openai-codex:gpt-5.5").unwrap();
    let second = binding.reserve("openai-codex:gpt-5.5").unwrap();
    assert_ne!(first.request_id(), second.request_id());
    binding.settle(first, known_cost(0.2)).unwrap();
    drop(second);
    let mut revised = approval(5, 1);
    revised.expected_revision = 1;
    ledger.approve_allowance(&revised).unwrap();
    assert!(binding.validate_model("openai-codex:gpt-5.5").is_err());
    assert!(binding.reserve("openai-codex:gpt-5.5").is_err());
    let current = AllowanceBinding::new(ledger.clone(), bound_work(2)).unwrap();
    drop(current.reserve("openai-codex:gpt-5.5").unwrap());
    let snapshot = ledger.allowance_snapshot("study-one").unwrap();
    assert_eq!(snapshot.committed_calls, 3);
    assert_eq!(snapshot.unresolved_calls, 2);
}

#[test]
fn binding_rejects_invalid_identity_before_runtime_execution() {
    let ledger = std::sync::Arc::new(fresh(2, 1));
    let mut work = bound_work(1);
    work.run_id = "../outside".into();
    assert!(AllowanceBinding::new(ledger.clone(), work).is_err());
    assert!(AllowanceBinding::new(ledger.clone(), bound_work(0)).is_err());
    assert_eq!(ledger.allowance_snapshot("study-one").unwrap().committed_calls, 0);
}

#[test]
fn no_allowance_means_no_admission() {
    let ledger = SpendLimiter::open_in_memory().unwrap();
    let error = ledger.reserve_provider_call(&call("first", InvestigationWork::Context)).unwrap_err();
    assert!(matches!(error.downcast_ref(), Some(AllowanceError::NotApproved(_))));
}

#[test]
fn every_phase_shares_the_allowance_and_protects_review() {
    let ledger = fresh(5, 2);
    for (id, work) in [("map", InvestigationWork::Context), ("scopes", InvestigationWork::Scope), ("pass-one", InvestigationWork::Discovery)] {
        let _reservation = ledger.reserve_provider_call(&call(id, work)).unwrap();
    }
    assert!(ledger.reserve_provider_call(&call("lesson", InvestigationWork::Learning)).is_err());
    let _review = ledger.reserve_provider_call(&call("triage", InvestigationWork::Review)).unwrap();
    let _report = ledger.reserve_provider_call(&call("report", InvestigationWork::Report)).unwrap();
    assert!(ledger.reserve_provider_call(&call("extra-review", InvestigationWork::Review)).is_err());
    let status = ledger.allowance_snapshot("study-one").unwrap();
    assert_eq!(status.committed_calls, 5);
    assert_eq!(status.review_calls, 2);
    assert_eq!(status.remaining_calls(), 0);
    assert_eq!(status.unresolved_calls, 5);
    assert_eq!(status.cost.exact_usd(), None);
}

#[test]
fn receipts_never_refund_call_slots_and_unknown_dollars_remain_unknown() {
    let ledger = fresh(3, 0);
    let zero = ledger.reserve_provider_call(&call("zero", InvestigationWork::Discovery)).unwrap();
    ledger.settle_provider_call(zero, known_cost(0.0)).unwrap();
    let unknown = ledger.reserve_provider_call(&call("unknown", InvestigationWork::Discovery)).unwrap();
    ledger.settle_provider_call(unknown, RuntimeCostReport::UNAVAILABLE).unwrap();
    let paid = ledger.reserve_provider_call(&call("paid", InvestigationWork::Discovery)).unwrap();
    ledger.settle_provider_call(paid, known_cost(0.5)).unwrap();
    let status = ledger.allowance_snapshot("study-one").unwrap();
    assert_eq!(status.remaining_calls(), 0);
    assert_eq!(status.unresolved_calls, 0);
    assert_eq!(status.cost.observed_usd_if_available(), Some(0.5));
    assert_eq!(status.cost.exact_usd(), None);
}

#[test]
fn cancellation_and_restart_keep_reservations_committed() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ledger.sqlite3");
    let ledger = SpendLimiter::open(&path).unwrap();
    ledger.approve_allowance(&approval(1, 0)).unwrap();
    drop(ledger.reserve_provider_call(&call("interrupted", InvestigationWork::Discovery)).unwrap());
    drop(ledger);
    let resumed = SpendLimiter::open(&path).unwrap();
    let status = resumed.allowance_snapshot("study-one").unwrap();
    assert_eq!(status.unresolved_calls, 1);
    assert_eq!(status.remaining_calls(), 0);
    assert!(resumed.reserve_provider_call(&call("retry", InvestigationWork::Discovery)).is_err());
}

#[test]
fn retries_require_distinct_reservations_and_cannot_reuse_a_request_id() {
    let ledger = fresh(2, 0);
    let request = call("first", InvestigationWork::Discovery);
    let first = ledger.reserve_provider_call(&request).unwrap();
    ledger.settle_provider_call(first, RuntimeCostReport::UNAVAILABLE).unwrap();
    let error = ledger.reserve_provider_call(&request).unwrap_err();
    assert!(matches!(error.downcast_ref(), Some(AllowanceError::AlreadyReserved(_))));
    let _retry = ledger.reserve_provider_call(&call("retry", InvestigationWork::Discovery)).unwrap();
    assert_eq!(ledger.allowance_snapshot("study-one").unwrap().remaining_calls(), 0);
}

#[test]
fn changing_allowance_requires_current_revision_and_preserves_consumption() {
    let ledger = fresh(2, 1);
    let _first = ledger.reserve_provider_call(&call("first", InvestigationWork::Discovery)).unwrap();
    let mut revised = approval(4, 2);
    assert!(ledger.approve_allowance(&revised).is_err());
    revised.expected_revision = 1;
    let status = ledger.approve_allowance(&revised).unwrap();
    assert_eq!(status.revision, 2);
    assert_eq!(status.committed_calls, 1);
    assert_eq!(status.remaining_discovery_calls(), 1);
    let mut request = call("second", InvestigationWork::Discovery);
    assert!(ledger.reserve_provider_call(&request).is_err());
    request.expected_revision = 2;
    let _second = ledger.reserve_provider_call(&request).unwrap();
    assert_eq!(ledger.allowance_snapshot("study-one").unwrap().remaining_discovery_calls(), 0);
}

#[test]
fn a_revision_cannot_erase_commitments_or_protected_review() {
    let ledger = fresh(3, 1);
    let _first = ledger.reserve_provider_call(&call("first", InvestigationWork::Discovery)).unwrap();
    let mut revised = approval(1, 1);
    revised.expected_revision = 1;
    assert!(ledger.approve_allowance(&revised).is_err());
    assert_eq!(ledger.allowance_snapshot("study-one").unwrap().revision, 1);
}

#[test]
fn model_mismatch_is_refused_without_reserving_a_call() {
    let ledger = fresh(2, 1);
    let mut request = call("wrong-model", InvestigationWork::Discovery);
    request.model = "openai-codex:other-model".into();
    let error = ledger.reserve_provider_call(&request).unwrap_err();
    assert!(matches!(error.downcast_ref(), Some(AllowanceError::ModelMismatch)));
    assert_eq!(ledger.allowance_snapshot("study-one").unwrap().committed_calls, 0);
}

#[test]
fn reservation_cannot_settle_another_investigations_ledger() {
    let first = fresh(1, 0);
    let second = fresh(1, 0);
    let request = call("first", InvestigationWork::Discovery);
    let ticket = first.reserve_provider_call(&request).unwrap();
    let _other = second.reserve_provider_call(&request).unwrap();
    assert!(second.settle_provider_call(ticket, known_cost(0.0)).is_err());
    assert_eq!(second.allowance_snapshot("study-one").unwrap().unresolved_calls, 1);
    assert_eq!(first.allowance_snapshot("study-one").unwrap().unresolved_calls, 1);
}

#[test]
fn approval_validation_rejects_invalid_versions_identities_models_and_limits() {
    let ledger = SpendLimiter::open_in_memory().unwrap();
    for invalid in [approval(0, 0), approval(2, 3)] {
        assert!(ledger.approve_allowance(&invalid).is_err());
    }
    let mut invalid = approval(2, 1);
    invalid.schema_version = 2;
    assert!(ledger.approve_allowance(&invalid).is_err());
    invalid.schema_version = 1;
    invalid.investigation_id = "../escape".into();
    assert!(ledger.approve_allowance(&invalid).is_err());
    invalid.investigation_id = "study-one".into();
    invalid.model = String::new();
    assert!(ledger.approve_allowance(&invalid).is_err());
}

#[test]
fn independent_workers_cannot_consume_protected_review_calls() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ledger.sqlite3");
    let owner = SpendLimiter::open(&path).unwrap();
    owner.approve_allowance(&approval(5, 2)).unwrap();
    let workers: Vec<_> = (0..12).map(|_| SpendLimiter::open(&path).unwrap()).collect();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(workers.len()));
    let threads: Vec<_> = workers.into_iter().enumerate().map(|(index, worker)| {
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            worker.reserve_provider_call(&call(&format!("worker-{index}"), InvestigationWork::Discovery)).is_ok()
        })
    }).collect();
    let admitted = threads.into_iter().map(|thread| usize::from(thread.join().unwrap())).sum::<usize>();
    assert_eq!(admitted, 3);
    let status = owner.allowance_snapshot("study-one").unwrap();
    assert_eq!(status.remaining_calls(), 2);
    assert_eq!(status.remaining_discovery_calls(), 0);
}
