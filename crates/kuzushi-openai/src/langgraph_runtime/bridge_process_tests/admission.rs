use super::super::{runtime_config::LangGraphRuntime, ResponseTextEvent, ResponseTextObserver};
use super::*;
use kuzushi_core::{
    allowance::{
        AllowanceApprovalV1, AllowanceBinding, AllowanceLimits, AllowanceWork, InvestigationWork,
    },
    AgentQueryRequest, AgentRuntime, RuntimeFailure, RuntimeFailureClass, SpendLimiter, V2Config,
};
use std::sync::Arc;

mod dispatch;
mod fixture;
use fixture::{Fixture, MODEL};

fn assert_allowance_refusal(error: anyhow::Error) {
    let failure = error
        .downcast_ref::<RuntimeFailure>()
        .expect("typed allowance failure");
    assert_eq!(
        failure.metadata().error_class,
        RuntimeFailureClass::AllowanceRefused
    );
}

#[test]
fn admission_counts_internal_model_turns_and_preserves_review_calls() {
    let fixture = Fixture::new("loop", 3, 1);
    assert_allowance_refusal(fixture.query(true).unwrap_err());
    assert_eq!(fixture.provider_calls(), 2);
    let snapshot = fixture.ledger.allowance_snapshot("offline-study").unwrap();
    assert_eq!(snapshot.committed_calls, 2);
    assert_eq!(snapshot.protected_review_remaining(), 1);
    assert_eq!(snapshot.unresolved_calls, 0);
    assert_eq!(snapshot.cost.exact_usd(), None);
    assert_eq!(snapshot.cost.observed_usd_if_available(), None);
}

#[test]
fn admission_counts_every_outer_transport_retry_before_fetch() {
    let fixture = Fixture::new("fail", 3, 1);
    assert_allowance_refusal(fixture.query(false).unwrap_err());
    assert_eq!(fixture.provider_calls(), 2);
    assert_eq!(
        fixture
            .ledger
            .allowance_snapshot("offline-study")
            .unwrap()
            .committed_calls,
        2
    );
}

#[test]
fn admission_counts_quota_retries_inside_one_bridge_process() {
    let fixture = Fixture::new("quota", 3, 1);
    assert_allowance_refusal(fixture.query(false).unwrap_err());
    assert_eq!(fixture.provider_calls(), 2);
    let starts = fs::read_to_string(fixture.root.path().join("bridge-starts")).unwrap();
    assert_eq!(starts.lines().count(), 1);
    let snapshot = fixture.ledger.allowance_snapshot("offline-study").unwrap();
    assert_eq!(snapshot.committed_calls, 2);
    assert_eq!(snapshot.protected_review_remaining(), 1);
}

#[test]
fn admission_preserves_the_existing_internal_turn_limit_without_adding_work() {
    let fixture = Fixture::new("loop", 14, 1);
    let response = fixture.query(true).unwrap();
    assert!(response.truncated);
    assert_eq!(response.stop_reason.as_deref(), Some("model_turn_limit"));
    assert_eq!(fixture.provider_calls(), 12);
    let snapshot = fixture.ledger.allowance_snapshot("offline-study").unwrap();
    assert_eq!(snapshot.committed_calls, 12);
    assert_eq!(snapshot.remaining_calls(), 2);
}

#[test]
fn admission_keeps_cancelled_inflight_cost_unresolved_after_restart() {
    let mut fixture = Fixture::new("cancel", 2, 1);
    let cancellation = kuzushi_core::ScanCancellation::default();
    let signal = cancellation.clone();
    fixture.runtime.cancellation = Some(cancellation);
    fixture.runtime.response_text = Some(ResponseTextObserver::new(move |event| {
        if matches!(event, ResponseTextEvent::Delta(_)) {
            signal.cancel();
        }
    }));
    let started = Instant::now();
    assert!(fixture.query(false).is_err());
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(fixture.provider_calls(), 1);
    let reopened = SpendLimiter::open(fixture.root.path().join("ledger.sqlite3")).unwrap();
    let snapshot = reopened.allowance_snapshot("offline-study").unwrap();
    assert_eq!(snapshot.unresolved_calls, 1);
    assert_eq!(snapshot.remaining_discovery_calls(), 0);
    assert_eq!(snapshot.cost.exact_usd(), None);
}

#[test]
fn admission_rejects_old_bridges_instead_of_accepting_an_unaccounted_result() {
    let mut fixture = Fixture::new("loop", 2, 1);
    fixture.runtime.command = vec![
        "python3".into(),
        "-c".into(),
        "print('{\"ok\":true,\"text\":\"unaccounted\"}')".into(),
    ];
    let error = fixture.query(false).unwrap_err();
    let failure = error.downcast_ref::<RuntimeFailure>().unwrap();
    assert_eq!(
        failure.metadata().error_class,
        RuntimeFailureClass::AllowanceRefused
    );
    assert!(failure
        .metadata()
        .detail
        .as_ref()
        .unwrap()
        .contains("does not enforce"));
    assert_eq!(fixture.provider_calls(), 0);
}

#[test]
fn admission_survives_tracing_and_records_the_bounded_call() {
    use kuzushi_core::run_lifecycle::RunObservationHandle;
    let fixture = Fixture::new("loop", 2, 1);
    let observation = RunObservationHandle::jsonl(fixture.root.path(), "traced-call").unwrap();
    let traced =
        kuzushi_core::runtime::TracedRuntime::new(&fixture.runtime, observation.trace_handle());
    let bound = traced
        .with_allowance_binding(fixture.binding.clone())
        .unwrap();
    assert_eq!(
        bound.query_blocking(fixture.request(false)).unwrap().text,
        "bounded conclusion"
    );
    assert_allowance_refusal(bound.query_blocking(fixture.request(false)).unwrap_err());
    assert_eq!(fixture.provider_calls(), 1);
    observation.flush().unwrap();
    assert_two_traced_calls(fixture.root.path());
    assert_failure_recovery(fixture.root.path());
    assert_eq!(
        fixture
            .ledger
            .allowance_snapshot("offline-study")
            .unwrap()
            .committed_calls,
        1
    );
}

#[test]
fn admission_next_step_uses_the_same_durable_allowance() {
    let mut fixture = Fixture::new("loop", 2, 1);
    fixture.runtime.thinking_level = Some("medium".into());
    let bound = fixture
        .runtime
        .with_allowance_binding(fixture.binding.clone())
        .unwrap();
    let request = kuzushi_core::AgentToolLoopRequest {
        model: MODEL.into(),
        cwd: fixture.root.path().into(),
        system_prompt: "Offline accounting test".into(),
        prompt: "Inspect source only".into(),
        tools: vec![],
        max_steps: 1,
        temperature: None,
        runtime_options: Default::default(),
    };
    assert!(matches!(
        bound.next_step_blocking(&request, &[]).unwrap(),
        kuzushi_core::AgentLoopStep::Final { .. }
    ));
    assert_allowance_refusal(fixture.query(false).unwrap_err());
    assert_eq!(fixture.provider_calls(), 1);
}

#[test]
fn admission_parallel_bridges_cannot_spend_the_protected_review_calls() {
    let fixture = Fixture::new("loop", 3, 1);
    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| fixture.query(false)))
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 2);
    for error in results.into_iter().filter_map(Result::err) {
        assert_allowance_refusal(error);
    }
    assert_eq!(fixture.provider_calls(), 2);
    assert_eq!(
        fixture
            .ledger
            .allowance_snapshot("offline-study")
            .unwrap()
            .protected_review_remaining(),
        1
    );
}

#[test]
fn admission_old_eof_bridge_stops_at_the_handshake_deadline() {
    let mut fixture = Fixture::new("loop", 2, 1);
    fixture.runtime.command = vec![
        "python3".into(),
        "-c".into(),
        "import sys; sys.stdin.read(); print('{\"ok\":true,\"text\":\"unaccounted\"}')".into(),
    ];
    let started = Instant::now();
    let error = fixture.query(false).unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(15));
    let metadata = error.downcast_ref::<RuntimeFailure>().unwrap().metadata();
    assert_eq!(metadata.error_class, RuntimeFailureClass::AllowanceRefused);
    assert!(metadata
        .detail
        .as_ref()
        .unwrap()
        .contains("startup deadline"));
    assert_eq!(fixture.provider_calls(), 0);
    assert_eq!(
        fixture
            .ledger
            .allowance_snapshot("offline-study")
            .unwrap()
            .committed_calls,
        0
    );
}

fn assert_two_traced_calls(root: &std::path::Path) {
    use kuzushi_core::run_lifecycle::{read_run_items, RunItemV1};
    let items = read_run_items(root, "traced-call").unwrap().unwrap();
    assert_eq!(
        items
            .items
            .iter()
            .filter(|row| matches!(row.item, RunItemV1::ModelCallStarted { .. }))
            .count(),
        2
    );
    assert_eq!(
        items
            .items
            .iter()
            .filter(|row| matches!(row.item, RunItemV1::ModelCallFinished { .. }))
            .count(),
        2
    );
}

fn assert_failure_recovery(root: &std::path::Path) {
    use kuzushi_core::run_artifacts::{write_run_failures, RunFailures};
    write_run_failures(
        root,
        "traced-call",
        "agentic-sast:scan",
        "failed",
        "Investigation allowance refused",
        &[],
    )
    .unwrap();
    let path = root.join(".kuzushi/v3/runs/traced-call/failures.json");
    let failures: RunFailures = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let failure = &failures.failures[0];
    assert_eq!(
        failure.runtime_failure.as_ref().unwrap().error_class,
        RuntimeFailureClass::AllowanceRefused
    );
    let recovery = failure.agent_thread_context.recovery_options.join("\n");
    assert!(recovery.contains("Finish and report"));
    assert!(recovery.contains("approve a specific allowance revision"));
    assert!(!recovery.contains("resume automatically"));
}
