use super::*;

pub(crate) fn scan_trace_handle(
    target: &std::path::Path,
    run_id: &str,
    sink: JobEventSink,
    attempt_id: Option<kuzushi_core::run_lifecycle::RunAttemptId>,
    task_id: kuzushi_core::run_lifecycle::RunTaskId,
) -> anyhow::Result<TraceHandle> {
    let mut observation = scan_observation(target, run_id, sink)?;
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
) -> anyhow::Result<kuzushi_core::run_lifecycle::RunObservationHandle> {
    let (item_subscriber, range_subscriber, derivative_subscriber, fault_subscriber) =
        sink.run_lifecycle_subscribers(run_id);
    kuzushi_core::run_lifecycle::RunObservationHandle::jsonl_with_derivative_delivery_subscriber(
        target,
        run_id,
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
    fn scan_trace_handle_delivers_and_writes_typed_items() {
        let temp = tempfile::tempdir().unwrap();
        let mut hub = JobHub::default();
        let ticket = hub.start(JobKind::Run, "scan");
        let trace = scan_trace_handle(
            temp.path(),
            "scan-trace",
            ticket.sink(),
            None,
            kuzushi_core::run_lifecycle::RunTaskId::new(),
        )
        .unwrap();

        trace.step("tool", "scan", "started").emit();
        trace.run_observation().unwrap().flush().unwrap();

        let delivered = hub
            .drain(32)
            .into_iter()
            .find(|event| matches!(event, ShellEvent::RunItem(_)))
            .expect("typed lifecycle item should be delivered live");
        let items_path =
            kuzushi_core::run_artifacts::run_dir(temp.path(), "scan-trace").join("items.jsonl");
        let persisted = std::fs::read_to_string(items_path).unwrap();

        assert!(matches!(delivered, ShellEvent::RunItem(_)));
        assert!(persisted.contains("diagnostic_notice"), "{persisted}");
    }
}
