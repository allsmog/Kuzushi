use super::*;
use crate::run_artifacts::run_dir;
use std::sync::Mutex;
use std::sync::mpsc;

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
fn delayed_builder_does_not_reserve_trace_number() {
    let sink = Arc::new(VecSink::default());
    let handle = TraceHandle::new(sink.clone()).for_tool("semgrep:scan");

    let delayed = handle.step("tool", "scan", "created first");
    let emitted_first = handle.step("tool", "scan", "emitted first").emit();
    let emitted_second = delayed.emit();

    assert_eq!((emitted_first, emitted_second), (1, 2));
    let steps = sink.steps.lock().unwrap();
    let labels: Vec<_> = steps
        .iter()
        .map(|step| (step.n, step.label.as_str()))
        .collect();
    assert_eq!(labels, vec![(1, "emitted first"), (2, "created first")]);
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

#[tokio::test]
async fn task_local_parent_scope_survives_await() {
    let sink = Arc::new(VecSink::default());
    let handle = TraceHandle::new(sink.clone()).for_module("verify");
    let parent = handle.step("tool", "finding", "evidence-pull").emit();

    handle
        .with_parent_scope(parent, async {
            // A scheduler yield mid-scope is exactly where the old thread-local
            // stack could lose the parent; the task-local must carry it through.
            tokio::task::yield_now().await;
            let _ = handle.step("reasoning", "finding", "after await").emit();
        })
        .await;

    // Back outside the scope.
    let _ = handle.step("done", "finding", "complete").emit();

    let steps = sink.steps.lock().unwrap();
    assert_eq!(steps[1].parent_step, Some(parent));
    assert_eq!(steps[2].parent_step, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn task_local_parent_scope_survives_thread_hops() {
    let sink = Arc::new(VecSink::default());
    let handle = TraceHandle::new(sink.clone()).for_module("triage");
    let parent = handle.step("tool", "run", "root").emit();

    with_parent_step(parent, async {
        // Many yields give the multi-thread scheduler opportunities to resume
        // this task on a different worker thread; parent linkage must hold.
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        let _ = handle.step("reasoning", "run", "child").emit();
    })
    .await;

    let steps = sink.steps.lock().unwrap();
    assert_eq!(steps[1].parent_step, Some(parent));
}

#[tokio::test]
async fn explicit_child_handle_links_inside_spawned_task() {
    // `tokio::spawn` does not inherit task-locals, so a detached task must be
    // handed an explicit `child` handle — its parent linkage is `Send` and
    // travels with the handle.
    let sink = Arc::new(VecSink::default());
    let handle = TraceHandle::new(sink.clone()).for_module("verify");
    let parent = handle.step("tool", "finding", "root").emit();
    let child = handle.child(parent);

    tokio::spawn(async move {
        let _ = child.step("reasoning", "finding", "in spawn").emit();
    })
    .await
    .unwrap();

    let steps = sink.steps.lock().unwrap();
    assert_eq!(steps[1].parent_step, Some(parent));
}

#[test]
fn multiple_jsonl_handles_share_monotonic_step_numbers() {
    let tmp = tempfile::tempdir().unwrap();
    // Two independent roots for the same run — previously each seeded its own
    // counter and could mint colliding step numbers.
    let h1 = TraceHandle::jsonl(tmp.path(), "run-shared").for_tool("triage:run");
    let h2 = TraceHandle::jsonl(tmp.path(), "run-shared").for_tool("verify:finding");

    let a = h1.step("tool", "run", "a").emit();
    let b = h2.step("tool", "finding", "b").emit();
    let c = h1.step("tool", "run", "c").emit();
    let d = h2.step("tool", "finding", "d").emit();

    assert_eq!((a, b, c, d), (1, 2, 3, 4));

    let trace =
        std::fs::read_to_string(run_dir(tmp.path(), "run-shared").join("trace.jsonl")).unwrap();
    let numbers: Vec<u64> = trace
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["n"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(numbers, vec![1, 2, 3, 4]);
}

#[test]
fn concurrent_trace_appends_do_not_tear_lines() {
    use std::thread;

    let tmp = tempfile::tempdir().unwrap();
    let target = Arc::new(tmp.path().to_path_buf());

    let mut handles = Vec::new();
    for worker in 0..8u64 {
        let target = Arc::clone(&target);
        handles.push(thread::spawn(move || {
            for i in 0..50u64 {
                let step = RunTraceStep::new(
                    (worker * 100 + i + 1) as usize,
                    "tool",
                    format!("w{worker}-i{i}"),
                );
                append_run_trace_step(target.as_path(), "run-cc", &step).unwrap();
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }

    let trace =
        std::fs::read_to_string(run_dir(target.as_path(), "run-cc").join("trace.jsonl")).unwrap();
    let lines: Vec<&str> = trace
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), 8 * 50);
    // Serialized appends mean every line is a whole record — never two writes
    // spliced together.
    for line in lines {
        serde_json::from_str::<RunTraceStep>(line).expect("each appended line must be intact");
    }
}

#[test]
fn jsonl_sink_surfaces_append_failure_instead_of_swallowing() {
    let tmp = tempfile::tempdir().unwrap();
    // Block the run directory by planting a file where the dir must be, so the
    // append fails. The sink must record the failure, not drop it silently.
    let runs = crate::run_artifacts::runs_root(tmp.path());
    std::fs::create_dir_all(&runs).unwrap();
    std::fs::write(runs.join("run-bad"), "not a directory").unwrap();

    let sink = JsonlSink::new(tmp.path().to_path_buf(), "run-bad");
    sink.record(&RunTraceStep::new(1, "tool", "will fail"));

    assert_eq!(sink.append_failures(), 1);
}
