use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{append_run_trace_step, RunTraceStep};

thread_local! {
    /// Per-thread parent-step stack. Producers push via
    /// `TraceHandle::parent_scope(n)` to scope subsequent runtime
    /// instrumentation under a labelled phase header. The wrapping
    /// `TracedRuntime` reads the top of stack when emitting child events.
    static PARENT_STACK: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// RAII guard returned by `TraceHandle::parent_scope`. Pops the parent stack
/// on drop so callers can't accidentally leak nesting across calls.
pub struct ParentScope {
    _private: (),
}

impl Drop for ParentScope {
    fn drop(&mut self) {
        PARENT_STACK.with(|stack| {
            stack.borrow_mut().pop();
        });
    }
}

/// Top of the per-thread parent stack, if any. Returns `None` when no
/// `parent_scope` is active. Used by both `TraceHandle::step` (for steps
/// emitted by producers without an explicit `child(n)`) and by
/// `TracedRuntime` to thread runtime calls under the producer's current
/// phase header.
pub fn current_parent_step() -> Option<usize> {
    PARENT_STACK.with(|stack| stack.borrow().last().copied())
}

pub trait TraceSink: Send + Sync {
    fn record(&self, step: &RunTraceStep);
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
        Self {
            inner: Arc::new(TraceHandleInner {
                sink,
                counter: AtomicUsize::new(0),
            }),
            module_id: None,
            parent_step: None,
        }
    }

    pub fn for_module(&self, module_id: impl Into<String>) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            module_id: Some(Arc::from(module_id.into())),
            parent_step: self.parent_step,
        }
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
        // Explicit child handle wins; otherwise fall back to thread-local
        // parent stack populated by `parent_scope` guards.
        let parent = self.parent_step.or_else(current_parent_step);
        if let Some(parent_step) = parent {
            step.parent_step = Some(parent_step);
        }
        TraceStepBuilder {
            handle: self,
            step: Some(step),
        }
    }

    /// Push `parent` onto the per-thread parent stack and return an RAII
    /// guard that pops it on drop. Subsequent step emissions through this
    /// handle (and any `TracedRuntime` instrumentation on the same thread)
    /// will set `parent_step` to `parent` while the guard is alive.
    ///
    /// The producer pattern is:
    /// ```ignore
    /// let phase = trace.step("reasoning", "run", "evidence-collect").emit();
    /// let _scope = trace.parent_scope(phase);
    /// // every runtime.query_blocking(...) call inside this block now
    /// // emits a child step under `phase`.
    /// ```
    pub fn parent_scope(&self, parent: usize) -> ParentScope {
        PARENT_STACK.with(|stack| {
            stack.borrow_mut().push(parent);
        });
        ParentScope { _private: () }
    }
}

pub struct TraceStepBuilder<'a> {
    handle: &'a TraceHandle,
    step: Option<RunTraceStep>,
}

impl<'a> TraceStepBuilder<'a> {
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

    /// Emit the step now and return its `n` so callers can pass it to
    /// `TraceHandle::child(n)` for indented sub-steps.
    pub fn emit(mut self) -> usize {
        let step = self.step.take().expect("step still present");
        let n = step.n;
        self.handle.inner.sink.record(&step);
        n
    }
}

impl<'a> Drop for TraceStepBuilder<'a> {
    fn drop(&mut self) {
        if let Some(step) = self.step.take() {
            self.handle.inner.sink.record(&step);
        }
    }
}

/// File sink — appends each step to `<runs_root>/.kuzushi/runs/<run_id>/trace.jsonl`.
/// IO errors are swallowed so producers never block on disk issues.
pub struct JsonlSink {
    workspace_root: PathBuf,
    run_id: String,
}

impl JsonlSink {
    pub fn new(workspace_root: impl Into<PathBuf>, run_id: impl Into<String>) -> Self {
        Self {
            workspace_root: workspace_root.into(),
            run_id: run_id.into(),
        }
    }
}

impl TraceSink for JsonlSink {
    fn record(&self, step: &RunTraceStep) {
        let _ = append_run_trace_step(&self.workspace_root, &self.run_id, step);
    }
}

/// Forwards every step to a `Sender<RunTraceStep>` after delegating to an inner
/// sink (typically `JsonlSink`). Best-effort send: a disconnected receiver is
/// silently ignored.
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
        let handle = TraceHandle::new(sink.clone()).for_module("semgrep");

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
    fn drop_emits_step_when_emit_not_called() {
        let sink = Arc::new(VecSink::default());
        let handle = TraceHandle::new(sink.clone()).for_module("verify");
        {
            let _builder = handle
                .step("tool", "finding", "evidence-pull")
                .with_latency_ms(43);
            // dropped without .emit()
        }
        let steps = sink.steps.lock().unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].latency_ms, Some(43));
    }
}
