use std::cell::RefCell;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{append_run_trace_step, next_run_trace_step_number, run_artifact_path, RunTraceStep};

thread_local! {
    static PARENT_STACK: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

tokio::task_local! {
    /// Innermost trace parent for the *current async task*. Unlike the
    /// thread-local `PARENT_STACK`, a task-local follows the task across
    /// `.await` points and worker-thread hops, so parent→child linkage
    /// survives async execution instead of being lost the moment the executor
    /// resumes the task on a different thread. Nesting works by shadowing:
    /// each `with_parent_step` scope overrides the outer value, and
    /// `try_with` returns the innermost.
    static TASK_PARENT_STEP: usize;
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

/// Run `fut` with `parent` established as the ambient trace parent for every
/// trace step emitted inside it — including across `.await` boundaries and
/// after the task migrates between runtime worker threads. This is the
/// async-safe counterpart to [`TraceHandle::parent_scope`], which only holds
/// for strictly synchronous same-thread nesting.
///
/// Spawned tasks (`tokio::spawn`) do NOT inherit the caller's task-locals; to
/// carry a parent into a detached task, either wrap that task's body in its
/// own `with_parent_step`, or hand it an explicit `TraceHandle::child(parent)`,
/// whose parent linkage is stored on the handle and is fully `Send`.
pub async fn with_parent_step<F, T>(parent: usize, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    TASK_PARENT_STEP.scope(parent, fut).await
}

pub fn current_parent_step() -> Option<usize> {
    // The task-local scope wins: it is correct under async execution. Fall back
    // to the thread-local stack for synchronous same-thread nesting. `try_with`
    // returns `Err` (never panics) when neither is set — e.g. a sync producer
    // running outside any Tokio task — so this stays safe off-runtime.
    if let Ok(parent) = TASK_PARENT_STEP.try_with(|parent| *parent) {
        return Some(parent);
    }
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
    counter: Arc<AtomicUsize>,
    emit_lock: Arc<Mutex<()>>,
    rejected_invalid_steps: AtomicU64,
}

impl TraceHandle {
    pub fn new(sink: Arc<dyn TraceSink>) -> Self {
        Self::with_counter(sink, 0)
    }

    pub fn with_initial_step_number(sink: Arc<dyn TraceSink>, initial_step_number: usize) -> Self {
        Self::with_counter(sink, initial_step_number)
    }

    fn with_counter(sink: Arc<dyn TraceSink>, initial_step_number: usize) -> Self {
        Self::with_shared_state(
            sink,
            Arc::new(AtomicUsize::new(initial_step_number)),
            Arc::new(Mutex::new(())),
        )
    }

    fn with_shared_state(
        sink: Arc<dyn TraceSink>,
        counter: Arc<AtomicUsize>,
        emit_lock: Arc<Mutex<()>>,
    ) -> Self {
        Self {
            inner: Arc::new(TraceHandleInner {
                sink,
                counter,
                emit_lock,
                rejected_invalid_steps: AtomicU64::new(0),
            }),
            module_id: None,
            parent_step: None,
        }
    }

    pub fn jsonl(target: impl Into<PathBuf>, run_id: impl Into<String>) -> Self {
        let target = target.into();
        let run_id = run_id.into();
        // Independent JSONL handles pointed at the same run must share one step
        // counter, otherwise two roots would both seed from the file and mint
        // colliding step numbers. Key a process-global counter by the resolved
        // trace path; the first handle seeds it from disk, later handles reuse
        // the in-memory value (which already reflects steps emitted this run).
        let trace_path = run_artifact_path(&target, &run_id, "trace.jsonl");
        let (counter, emit_lock) = shared_trace_state(&trace_path, || {
            next_run_trace_step_number(&target, &run_id).saturating_sub(1)
        });
        Self::with_shared_state(Arc::new(JsonlSink::new(target, run_id)), counter, emit_lock)
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
        let mut step = RunTraceStep::new(0, kind, label)
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

    /// Async-safe parent scoping. Prefer this over [`Self::parent_scope`] when
    /// the wrapped work contains `.await` points or may fan out across worker
    /// threads — the parent linkage is carried on a task-local and survives
    /// both. See [`with_parent_step`].
    pub async fn with_parent_scope<F, T>(&self, parent: usize, fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        with_parent_step(parent, fut).await
    }

    pub fn run_artifact_location(&self) -> Option<(PathBuf, String)> {
        self.inner.sink.run_artifact_location()
    }

    /// Invalid provider-cost metadata is rejected before it can reach any
    /// durable or live sink. The counter makes that diagnostic loss visible
    /// without panicking a product workflow for an auxiliary trace failure.
    pub fn rejected_invalid_steps(&self) -> u64 {
        self.inner.rejected_invalid_steps.load(Ordering::Relaxed)
    }

    fn record_step(&self, mut step: RunTraceStep) -> usize {
        if let Err(error) = super::write_run_artifact_json::validate_trace_step_cost(&step) {
            let rejected = self
                .inner
                .rejected_invalid_steps
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            eprintln!(
                "kuzushi: rejected invalid trace step #{rejected} before sink dispatch: {error:#}"
            );
            return 0;
        }
        let _guard = self
            .inner
            .emit_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let n = self.inner.counter.fetch_add(1, Ordering::Relaxed) + 1;
        step.n = n;
        self.inner.sink.record(&step);
        n
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
            step.observed_cost_usd = None;
            step.provider_spend_unresolved = false;
        }
        self
    }

    pub fn with_cost_report(mut self, report: crate::runtime::RuntimeCostReport) -> Self {
        if let Some(step) = self.step.take() {
            self.step = Some(step.with_cost_report(report));
        }
        self
    }

    pub fn with_call_attempted(mut self, attempted: bool) -> Self {
        if let Some(step) = self.step.as_mut() {
            step.call_attempted = Some(attempted);
        }
        self
    }

    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        if let Some(step) = self.step.as_mut() {
            step.severity = Some(severity.into());
        }
        self
    }

    pub fn with_model_metadata(
        mut self,
        model: impl Into<String>,
        provider: impl Into<String>,
        prompt_hash: impl Into<String>,
    ) -> Self {
        if let Some(step) = self.step.as_mut() {
            step.model = Some(model.into());
            step.provider = Some(provider.into());
            step.prompt_hash = Some(prompt_hash.into());
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
        self.handle.record_step(step)
    }
}

impl Drop for TraceStepBuilder<'_> {
    fn drop(&mut self) {
        if let Some(step) = self.step.take() {
            self.handle.record_step(step);
        }
    }
}

struct SharedTraceState {
    counter: Arc<AtomicUsize>,
    emit_lock: Arc<Mutex<()>>,
}

/// Process-global trace emission state, keyed by resolved trace-file path, so
/// all `TraceHandle::jsonl` roots targeting one run share numbering and serialize
/// the number+record critical section.
fn shared_trace_state(
    trace_path: &Path,
    seed: impl FnOnce() -> usize,
) -> (Arc<AtomicUsize>, Arc<Mutex<()>>) {
    static STATES: OnceLock<Mutex<HashMap<PathBuf, SharedTraceState>>> = OnceLock::new();
    let states = STATES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = states
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let state = map
        .entry(trace_path.to_path_buf())
        .or_insert_with(|| SharedTraceState {
            counter: Arc::new(AtomicUsize::new(seed())),
            emit_lock: Arc::new(Mutex::new(())),
        });
    (Arc::clone(&state.counter), Arc::clone(&state.emit_lock))
}

pub struct JsonlSink {
    target: PathBuf,
    run_id: String,
    append_failures: AtomicU64,
}

impl JsonlSink {
    pub fn new(target: impl Into<PathBuf>, run_id: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            run_id: run_id.into(),
            append_failures: AtomicU64::new(0),
        }
    }

    /// Number of trace-append failures observed by this sink. Surfaced instead
    /// of swallowed so a broken ledger is detectable in tests and operations.
    pub fn append_failures(&self) -> u64 {
        self.append_failures.load(Ordering::Relaxed)
    }
}

impl TraceSink for JsonlSink {
    fn record(&self, step: &RunTraceStep) {
        if let Err(error) = append_run_trace_step(&self.target, &self.run_id, step) {
            // Do not silently discard a failed ledger write: count it and warn
            // on stderr. The trace is diagnostic, so we don't unwind the caller,
            // but the failure must be observable rather than invisible.
            self.append_failures.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "kuzushi: failed to append run trace step to {} (run {}): {error:#}",
                self.target.display(),
                self.run_id
            );
        }
    }

    fn run_artifact_location(&self) -> Option<(PathBuf, String)> {
        Some((self.target.clone(), self.run_id.clone()))
    }
}

pub struct BroadcastSink {
    inner: Arc<dyn TraceSink>,
    tx: Sender<RunTraceStep>,
    dropped_live_sends: AtomicU64,
    rejected_invalid_steps: AtomicU64,
}

impl BroadcastSink {
    pub fn new(inner: Arc<dyn TraceSink>, tx: Sender<RunTraceStep>) -> Self {
        Self {
            inner,
            tx,
            dropped_live_sends: AtomicU64::new(0),
            rejected_invalid_steps: AtomicU64::new(0),
        }
    }

    pub fn dropped_live_sends(&self) -> u64 {
        self.dropped_live_sends.load(Ordering::Relaxed)
    }

    pub fn rejected_invalid_steps(&self) -> u64 {
        self.rejected_invalid_steps.load(Ordering::Relaxed)
    }
}

impl TraceSink for BroadcastSink {
    fn record(&self, step: &RunTraceStep) {
        if let Err(error) = super::write_run_artifact_json::validate_trace_step_cost(step) {
            let rejected = self.rejected_invalid_steps.fetch_add(1, Ordering::Relaxed) + 1;
            eprintln!(
                "kuzushi: rejected invalid live trace step #{rejected} before durable or broadcast dispatch: {error:#}"
            );
            return;
        }
        self.inner.record(step);
        if self.tx.send(step.clone()).is_err() {
            let dropped = self.dropped_live_sends.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped == 1 || dropped.is_power_of_two() {
                eprintln!(
                    "kuzushi: dropped {dropped} live trace broadcast(s); durable trace sink remains authoritative"
                );
            }
        }
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
mod tests;
