use super::*;
use crate::run_artifacts::run_dir;
use std::sync::mpsc;
use std::sync::Mutex;

#[derive(Default)]
struct VecSink {
    steps: Mutex<Vec<RunTraceStep>>,
}

impl TraceSink for VecSink {
    fn record(&self, step: &RunTraceStep) {
        self.steps.lock().unwrap().push(step.clone());
    }
}

#[test]
fn step_assigns_monotonic_n_and_stamps_module_id() {
    let sink = Arc::new(VecSink::default());
    let handle = TraceHandle::new(sink.clone()).for_tool("semgrep:scan");

    let n1 = handle.step("tool", "scan", "started").emit();
    let n2 = handle.step("tool", "scan", "complete").emit();

    assert_eq!(n1, 1);
    assert_eq!(n2, 2);
    let steps = sink.steps.lock().unwrap();
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0].module_id.as_deref(), Some("semgrep"));
    assert_eq!(steps[0].verb.as_deref(), Some("scan"));
    assert!(steps[0].started_at_ms.is_some());
}

#[test]
fn child_handle_stamps_parent_step() {
    let sink = Arc::new(VecSink::default());
    let handle = TraceHandle::new(sink.clone()).for_module("triage");
    let parent = handle.step("tool", "run", "load-finding").emit();
    let child = handle.child(parent);

    let _ = child.step("reasoning", "run", "classifying CWE-89").emit();

    let steps = sink.steps.lock().unwrap();
    assert_eq!(steps[0].parent_step, None);
    assert_eq!(steps[1].parent_step, Some(parent));
}

#[test]
fn parent_scope_threads_parent_step() {
    let sink = Arc::new(VecSink::default());
    let handle = TraceHandle::new(sink.clone()).for_module("verify");
    let parent = handle.step("tool", "finding", "evidence-pull").emit();
    {
        let _scope = handle.parent_scope(parent);
        let _ = handle.step("reasoning", "finding", "checking proof").emit();
    }
    let _ = handle.step("done", "finding", "complete").emit();

    let steps = sink.steps.lock().unwrap();
    assert_eq!(steps[1].parent_step, Some(parent));
    assert_eq!(steps[2].parent_step, None);
}

#[test]
fn broadcast_sink_writes_to_inner_and_channel() {
    let inner = Arc::new(VecSink::default());
    let inner_dyn: Arc<dyn TraceSink> = inner.clone();
    let (tx, rx) = mpsc::channel::<RunTraceStep>();
    let broadcast = Arc::new(BroadcastSink::new(inner_dyn, tx));
    let handle = TraceHandle::new(broadcast).for_module("semgrep");

    let _ = handle.step("tool", "scan", "started").emit();

    let received = rx
        .recv_timeout(std::time::Duration::from_millis(100))
        .unwrap();
    assert_eq!(received.module_id.as_deref(), Some("semgrep"));
    assert_eq!(inner.steps.lock().unwrap().len(), 1);
}

#[test]
fn drop_emits_step_when_emit_is_not_called() {
    let sink = Arc::new(VecSink::default());
    let handle = TraceHandle::new(sink.clone()).for_module("verify");
    {
        let _builder = handle
            .step("tool", "finding", "evidence-pull")
            .with_latency_ms(43);
    }

    let steps = sink.steps.lock().unwrap();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].latency_ms, Some(43));
}

#[test]
fn jsonl_sink_appends_trace_steps_to_run_artifact() {
    let tmp = tempfile::tempdir().unwrap();
    let handle = TraceHandle::jsonl(tmp.path(), "run-1").for_tool("triage:run");

    let _ = handle.step("reasoning", "run", "classified finding").emit();

    let trace_path = run_dir(tmp.path(), "run-1").join("trace.jsonl");
    let trace = std::fs::read_to_string(trace_path).unwrap();
    assert!(trace.contains("\"module_id\":\"triage\""));
    assert!(trace.contains("\"label\":\"classified finding\""));
}

#[test]
fn jsonl_handle_continues_existing_trace_numbering() {
    let tmp = tempfile::tempdir().unwrap();
    append_run_trace_step(
        tmp.path(),
        "run-1",
        &RunTraceStep::new(1, "tool", "triage:run started"),
    )
    .unwrap();
    let handle = TraceHandle::jsonl(tmp.path(), "run-1").for_tool("triage:run");

    let n = handle.step("reasoning", "run", "classified finding").emit();

    assert_eq!(n, 2);
}

#[test]
fn seeded_broadcast_handle_continues_existing_trace_numbering() {
    let inner = Arc::new(VecSink::default());
    let inner_dyn: Arc<dyn TraceSink> = inner.clone();
    let (tx, rx) = mpsc::channel::<RunTraceStep>();
    let broadcast = Arc::new(BroadcastSink::new(inner_dyn, tx));
    let handle = TraceHandle::with_initial_step_number(broadcast, 1).for_tool("triage:run");

    let n = handle.step("reasoning", "run", "classified finding").emit();

    assert_eq!(n, 2);
    assert_eq!(rx.recv().unwrap().n, 2);
}

#[test]
fn module_id_from_tool_name_handles_unprefixed_tools() {
    assert_eq!(module_id_from_tool_name("catalog"), "catalog");
    assert_eq!(module_id_from_tool_name("systems-hunt:run"), "systems-hunt");
}
