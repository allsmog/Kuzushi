use super::*;

pub(crate) fn scan_trace_handle(
    target: &std::path::Path,
    run_id: &str,
    sink: JobEventSink,
    trace_budget: LiveTraceBudget,
) -> TraceHandle {
    let inner_sink: Arc<dyn TraceSink> = Arc::new(JsonlSink::new(target.to_path_buf(), run_id));
    let broadcast_sink: Arc<dyn TraceSink> =
        Arc::new(StampedTraceSink::new(inner_sink, sink, trace_budget));
    let initial_step_number = next_run_trace_step_number(target, run_id).saturating_sub(1);
    TraceHandle::with_initial_step_number(broadcast_sink, initial_step_number)
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
        );

        trace.step("tool", "scan", "started").emit();

        let broadcast = hub
            .drain(1)
            .pop()
            .expect("trace step should broadcast to activity");
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
