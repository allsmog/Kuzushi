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
mod tests;
