use super::*;

pub(crate) fn scan_trace_handle(
    target: &std::path::Path,
    run_id: &str,
    sink: JobEventSink,
    trace_budget: LiveTraceBudget,
    attempt_id: Option<kuzushi_core::run_lifecycle::RunAttemptId>,
    task_id: kuzushi_core::run_lifecycle::RunTaskId,
) -> anyhow::Result<TraceHandle> {
    let mut observation = scan_observation(target, run_id, sink, trace_budget)?;
    if let Some(attempt_id) = attempt_id {
        observation = observation.for_attempt(attempt_id, crate::app::WorkflowPhase::Scan);
    }
    let plan = observation.start_plan_with_tasks(
        "accepted Scan plan",
        vec![(task_id, "Run the accepted Scan plan".to_string())],
    )?;
    Ok(plan.tasks()[0].observation().trace_handle())
}

fn scan_observation(
    target: &std::path::Path,
    run_id: &str,
    sink: JobEventSink,
    trace_budget: LiveTraceBudget,
) -> anyhow::Result<kuzushi_core::run_lifecycle::RunObservationHandle> {
    let inner_sink: Arc<dyn TraceSink> = Arc::new(JsonlSink::new(target.to_path_buf(), run_id));
    let broadcast_sink: Arc<dyn TraceSink> = Arc::new(StampedTraceSink::new(
        inner_sink,
        sink.clone(),
        trace_budget,
    ));
    let initial_step_number = next_run_trace_step_number(target, run_id).saturating_sub(1);
    let (item_subscriber, range_subscriber, derivative_subscriber, fault_subscriber) =
        sink.run_lifecycle_subscribers(run_id);
    kuzushi_core::run_lifecycle::RunObservationHandle::with_trace_sink_and_derivative_delivery_subscriber(
        target,
        run_id,
        broadcast_sink,
        initial_step_number,
        Some(item_subscriber),
        Some(range_subscriber),
        Some(derivative_subscriber),
        Some(fault_subscriber),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_trace_handle_broadcasts_and_writes_trace_jsonl() {
        let temp = tempfile::tempdir().unwrap();
        let mut hub = JobHub::default();
        let ticket = hub.start(JobKind::Run, "scan");
        let trace = scan_trace_handle(
            temp.path(),
            "scan-trace",
            ticket.sink(),
            LiveTraceBudget::new(),
            None,
            kuzushi_core::run_lifecycle::RunTaskId::new(),
        )
        .unwrap();

        trace.step("tool", "scan", "started").emit();

        let broadcast = hub
            .drain(32)
            .into_iter()
            .find(|event| matches!(event, ShellEvent::Trace(_)))
            .expect("trace step should broadcast alongside typed lifecycle events");
        let trace_path = kuzushi_core::run_artifacts::run_artifact_path(
            temp.path(),
            "scan-trace",
            "trace.jsonl",
        );
        let persisted = std::fs::read_to_string(trace_path).unwrap();

        let ShellEvent::Trace(step) = broadcast else {
            panic!("expected trace broadcast");
        };
        assert_eq!(step.label, "started");
        assert!(persisted.contains("\"label\":\"started\""), "{persisted}");
    }
}
