use std::cell::RefCell;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{append_run_trace_step, next_run_trace_step_number, RunTraceStep};

thread_local! {
    static PARENT_STACK: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

pub struct ParentScope {
    _private: (),
    _not_send: PhantomData<Rc<()>>,
}

impl Drop for ParentScope {
    fn drop(&mut self) {
        PARENT_STACK.with(|stack| {
            stack.borrow_mut().pop();
        });
    }
}

pub fn current_parent_step() -> Option<usize> {
    PARENT_STACK.with(|stack| stack.borrow().last().copied())
}

pub trait TraceSink: Send + Sync {
    fn record(&self, step: &RunTraceStep);

    fn run_artifact_location(&self) -> Option<(PathBuf, String)> {
        None
    }
}

#[derive(Clone)]
pub struct TraceHandle {
    inner: Arc<TraceHandleInner>,
    module_id: Option<Arc<str>>,
    parent_step: Option<usize>,
}

struct TraceHandleInner {
    sink: Arc<dyn TraceSink>,
    counter: AtomicUsize,
}

impl TraceHandle {
    pub fn new(sink: Arc<dyn TraceSink>) -> Self {
        Self::with_counter(sink, 0)
    }

    pub fn with_initial_step_number(sink: Arc<dyn TraceSink>, initial_step_number: usize) -> Self {
        Self::with_counter(sink, initial_step_number)
    }

    fn with_counter(sink: Arc<dyn TraceSink>, initial_step_number: usize) -> Self {
        Self {
            inner: Arc::new(TraceHandleInner {
                sink,
                counter: AtomicUsize::new(initial_step_number),
            }),
            module_id: None,
            parent_step: None,
        }
    }

    pub fn jsonl(target: impl Into<PathBuf>, run_id: impl Into<String>) -> Self {
        let target = target.into();
        let run_id = run_id.into();
        let initial_step_number = next_run_trace_step_number(&target, &run_id).saturating_sub(1);
        Self::with_counter(
            Arc::new(JsonlSink::new(target, run_id)),
            initial_step_number,
        )
    }

    pub fn for_module(&self, module_id: impl Into<String>) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            module_id: Some(Arc::from(module_id.into())),
            parent_step: self.parent_step,
        }
    }

    pub fn for_tool(&self, tool_name: &str) -> Self {
        self.for_module(module_id_from_tool_name(tool_name))
    }

    pub fn child(&self, parent_step: usize) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            module_id: self.module_id.clone(),
            parent_step: Some(parent_step),
        }
    }

    pub fn step<'a>(
        &'a self,
        kind: impl Into<String>,
        verb: impl Into<String>,
        label: impl Into<String>,
    ) -> TraceStepBuilder<'a> {
        let n = self.inner.counter.fetch_add(1, Ordering::Relaxed) + 1;
        let mut step = RunTraceStep::new(n, kind, label)
            .with_verb(verb)
            .with_started_at_ms(now_unix_ms());
        if let Some(module_id) = &self.module_id {
            step.module_id = Some(module_id.as_ref().to_string());
        }
        if let Some(parent_step) = self.parent_step.or_else(current_parent_step) {
            step.parent_step = Some(parent_step);
        }
        TraceStepBuilder {
            handle: self,
            step: Some(step),
        }
    }

    pub fn parent_scope(&self, parent: usize) -> ParentScope {
        PARENT_STACK.with(|stack| {
            stack.borrow_mut().push(parent);
        });
        ParentScope {
            _private: (),
            _not_send: PhantomData,
        }
    }

    pub fn run_artifact_location(&self) -> Option<(PathBuf, String)> {
        self.inner.sink.run_artifact_location()
    }
}

pub struct TraceStepBuilder<'a> {
    handle: &'a TraceHandle,
    step: Option<RunTraceStep>,
}

impl TraceStepBuilder<'_> {
    pub fn with_latency_ms(mut self, ms: u64) -> Self {
        if let Some(step) = self.step.as_mut() {
            step.latency_ms = Some(ms);
        }
        self
    }

    pub fn with_cost_usd(mut self, cost: f64) -> Self {
        if let Some(step) = self.step.as_mut() {
            step.cost_usd = Some(cost);
        }
        self
    }

    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        if let Some(step) = self.step.as_mut() {
            step.severity = Some(severity.into());
        }
        self
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        if let Some(step) = self.step.as_mut() {
            step.label = label.into();
        }
        self
    }

    pub fn emit(mut self) -> usize {
        let step = self
            .step
            .take()
            .expect("trace step should still be pending");
        let n = step.n;
        self.handle.inner.sink.record(&step);
        n
    }
}

impl Drop for TraceStepBuilder<'_> {
    fn drop(&mut self) {
        if let Some(step) = self.step.take() {
            self.handle.inner.sink.record(&step);
        }
    }
}

pub struct JsonlSink {
    target: PathBuf,
    run_id: String,
}

impl JsonlSink {
    pub fn new(target: impl Into<PathBuf>, run_id: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            run_id: run_id.into(),
        }
    }
}

impl TraceSink for JsonlSink {
    fn record(&self, step: &RunTraceStep) {
        let _ = append_run_trace_step(&self.target, &self.run_id, step);
    }

    fn run_artifact_location(&self) -> Option<(PathBuf, String)> {
        Some((self.target.clone(), self.run_id.clone()))
    }
}

pub struct BroadcastSink {
    inner: Arc<dyn TraceSink>,
    tx: Sender<RunTraceStep>,
}

impl BroadcastSink {
    pub fn new(inner: Arc<dyn TraceSink>, tx: Sender<RunTraceStep>) -> Self {
        Self { inner, tx }
    }
}

impl TraceSink for BroadcastSink {
    fn record(&self, step: &RunTraceStep) {
        self.inner.record(step);
        let _ = self.tx.send(step.clone());
    }

    fn run_artifact_location(&self) -> Option<(PathBuf, String)> {
        self.inner.run_artifact_location()
    }
}

fn module_id_from_tool_name(name: &str) -> &str {
    name.split_once(':')
        .map(|(prefix, _)| prefix)
        .unwrap_or(name)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let trace_path = tmp.path().join(".kuzushi/runs/run-1/trace.jsonl");
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
}
