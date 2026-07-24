use std::cell::RefCell;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use crate::run_lifecycle::{
    DiagnosticLevel, RunAttemptId, RunCallId, RunItemId, RunItemRecord, RunItemSource, RunItemV1,
    RunTaskId, SafeText,
};

thread_local! {
    static PARENT_STACK: RefCell<Vec<RunItemId>> = const { RefCell::new(Vec::new()) };
}

tokio::task_local! {
    static TASK_PARENT_ITEM: RunItemId;
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

pub async fn with_parent_step<F, T>(parent: RunItemId, future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    TASK_PARENT_ITEM.scope(parent, future).await
}

pub fn current_parent_step() -> Option<RunItemId> {
    TASK_PARENT_ITEM
        .try_with(|parent| *parent)
        .ok()
        .or_else(|| PARENT_STACK.with(|stack| stack.borrow().last().copied()))
}

#[derive(Clone)]
pub struct TraceHandle {
    inner: Arc<TraceHandleInner>,
    module_id: Option<Arc<str>>,
    parent_item_id: Option<RunItemId>,
    plan_item_id: Option<RunItemId>,
    plan_revision: u64,
    task_id: Option<RunTaskId>,
    task_item_id: Option<RunItemId>,
    task_title: Option<Arc<str>>,
    attempt_id: Option<RunAttemptId>,
    phase: Option<crate::WorkflowPhase>,
    call_id: Option<RunCallId>,
    call_item_id: Option<RunItemId>,
    reasoning_item_id: Option<RunItemId>,
}

struct TraceHandleInner {
    writer: crate::run_lifecycle::RunItemWriter,
    artifact_location: Option<(PathBuf, String)>,
}

impl TraceHandle {
    pub fn jsonl(target: impl Into<PathBuf>, run_id: impl Into<String>) -> Self {
        let target = target.into();
        let run_id = run_id.into();
        let writer = crate::run_lifecycle::RunItemWriter::open(&target, &run_id, None)
            .expect("open typed run-item writer");
        Self::from_writer(writer, Some((target, run_id)))
    }

    pub fn observed_jsonl_with_delivery_subscribers(
        target: impl Into<PathBuf>,
        run_id: impl Into<String>,
        subscriber: Option<crate::run_lifecycle::CommittedItemSubscriber>,
        range_subscriber: Option<crate::run_lifecycle::CommittedRangeSubscriber>,
        fault_subscriber: Option<crate::run_lifecycle::RunItemDeliveryFaultSubscriber>,
    ) -> anyhow::Result<Self> {
        Self::observed_jsonl_with_derivative_delivery_subscriber(
            target,
            run_id,
            subscriber,
            range_subscriber,
            None,
            fault_subscriber,
        )
    }

    pub(crate) fn observed_jsonl_with_derivative_delivery_subscriber(
        target: impl Into<PathBuf>,
        run_id: impl Into<String>,
        subscriber: Option<crate::run_lifecycle::CommittedItemSubscriber>,
        range_subscriber: Option<crate::run_lifecycle::CommittedRangeSubscriber>,
        derivative_subscriber: Option<crate::run_lifecycle::DerivativeRangeSubscriber>,
        fault_subscriber: Option<crate::run_lifecycle::RunItemDeliveryFaultSubscriber>,
    ) -> anyhow::Result<Self> {
        let target = target.into();
        let run_id = run_id.into();
        let writer = crate::run_lifecycle::RunItemWriter::open_with_derivative_delivery_subscriber(
            &target,
            &run_id,
            subscriber,
            range_subscriber,
            derivative_subscriber,
            fault_subscriber,
        )?;
        Ok(Self::from_writer(writer, Some((target, run_id))))
    }

    pub(crate) fn from_writer(
        writer: crate::run_lifecycle::RunItemWriter,
        artifact_location: Option<(PathBuf, String)>,
    ) -> Self {
        Self {
            inner: Arc::new(TraceHandleInner {
                writer,
                artifact_location,
            }),
            module_id: None,
            parent_item_id: None,
            plan_item_id: None,
            plan_revision: 0,
            task_id: None,
            task_item_id: None,
            task_title: None,
            attempt_id: None,
            phase: None,
            call_id: None,
            call_item_id: None,
            reasoning_item_id: None,
        }
    }

    pub fn for_module(&self, module_id: impl Into<String>) -> Self {
        let mut scoped = self.clone();
        scoped.module_id = Some(Arc::from(module_id.into()));
        scoped
    }

    pub fn for_tool(&self, tool_name: &str) -> Self {
        self.for_module(module_id_from_tool_name(tool_name))
    }

    pub fn child(&self, parent_item_id: RunItemId) -> Self {
        let mut scoped = self.clone();
        scoped.parent_item_id = Some(parent_item_id);
        scoped
    }

    pub fn step<'a>(
        &'a self,
        kind: impl Into<String>,
        verb: impl Into<String>,
        label: impl Into<String>,
    ) -> RunActivityBuilder<'a> {
        RunActivityBuilder {
            handle: self,
            pending: Some(PendingRunActivity {
                kind: kind.into(),
                verb: verb.into(),
                label: label.into(),
                severity: None,
                completed: None,
                total: None,
            }),
        }
    }

    pub fn parent_scope(&self, parent: RunItemId) -> ParentScope {
        PARENT_STACK.with(|stack| stack.borrow_mut().push(parent));
        ParentScope {
            _private: (),
            _not_send: PhantomData,
        }
    }

    pub async fn with_parent_scope<F, T>(&self, parent: RunItemId, future: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        with_parent_step(parent, future).await
    }

    pub fn run_artifact_location(&self) -> Option<(PathBuf, String)> {
        self.inner.artifact_location.clone()
    }

    pub fn run_observation(&self) -> Option<crate::run_lifecycle::RunObservationHandle> {
        Some(self.scoped_run_observation())
    }

    pub(crate) fn item_writer(&self) -> Option<&crate::run_lifecycle::RunItemWriter> {
        Some(&self.inner.writer)
    }

    fn scoped_run_observation(&self) -> crate::run_lifecycle::RunObservationHandle {
        let observation = crate::run_lifecycle::RunObservationHandle::from_trace(self.clone());
        let observation = self.apply_plan_scope(observation);
        let observation = self.apply_work_scope(observation);
        self.apply_attempt_scope(observation)
    }

    fn apply_plan_scope(
        &self,
        observation: crate::run_lifecycle::RunObservationHandle,
    ) -> crate::run_lifecycle::RunObservationHandle {
        self.plan_item_id.map_or(observation.clone(), |item_id| {
            observation.with_plan_scope(item_id, self.plan_revision)
        })
    }

    fn apply_work_scope(
        &self,
        observation: crate::run_lifecycle::RunObservationHandle,
    ) -> crate::run_lifecycle::RunObservationHandle {
        let observation = self
            .task_id
            .map_or(observation.clone(), |task_id| observation.for_task(task_id));
        let observation = match (self.task_item_id, self.task_title.as_deref()) {
            (Some(item_id), Some(title)) => observation.with_task_scope(item_id, title),
            _ => observation,
        };
        self.parent_item_id.map_or(observation.clone(), |parent| {
            observation.with_parent(parent)
        })
    }

    fn apply_attempt_scope(
        &self,
        observation: crate::run_lifecycle::RunObservationHandle,
    ) -> crate::run_lifecycle::RunObservationHandle {
        match (self.attempt_id, self.phase) {
            (Some(attempt_id), Some(phase)) => observation.for_attempt(attempt_id, phase),
            _ => observation,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_run_item_scope(
        &self,
        plan_item_id: Option<RunItemId>,
        plan_revision: u64,
        task_id: Option<RunTaskId>,
        task_item_id: Option<RunItemId>,
        task_title: Option<String>,
        parent_item_id: Option<RunItemId>,
        attempt_id: Option<RunAttemptId>,
        phase: Option<crate::WorkflowPhase>,
    ) -> Self {
        let mut scoped = self.clone();
        scoped.plan_item_id = plan_item_id;
        scoped.plan_revision = plan_revision;
        scoped.task_id = task_id;
        scoped.task_item_id = task_item_id;
        scoped.task_title = task_title.map(Arc::from);
        scoped.parent_item_id = parent_item_id;
        scoped.attempt_id = attempt_id;
        scoped.phase = phase;
        scoped
    }

    pub(crate) fn with_run_call_scope(
        &self,
        call_id: RunCallId,
        item_id: RunItemId,
        parent_item_id: Option<RunItemId>,
    ) -> Self {
        let mut scoped = self.clone();
        scoped.call_id = Some(call_id);
        scoped.call_item_id = Some(item_id);
        scoped.parent_item_id = parent_item_id;
        scoped.reasoning_item_id = Some(RunItemId::new());
        scoped
    }

    fn record_activity(&self, activity: PendingRunActivity) -> RunItemId {
        let item_id = self.item_id_for(&activity);
        let record = self.activity_record(item_id, &activity);
        let coalescible = matches!(
            &record.item,
            RunItemV1::ToolCallProgress { .. } | RunItemV1::SafeReasoningSummary { .. }
        );
        let result = if coalescible {
            self.inner.writer.emit_coalescible(record)
        } else {
            self.inner.writer.emit(record)
        };
        if let Err(error) = result {
            crate::runtime_diagnostics::record_runtime_diagnostic(
                "run-lifecycle",
                format!("failed to record typed run activity: {error:#}"),
            );
        }
        item_id
    }

    fn item_id_for(&self, activity: &PendingRunActivity) -> RunItemId {
        match activity.kind.as_str() {
            "tool-progress" => self.call_item_id.unwrap_or_else(RunItemId::new),
            "reasoning" => self.reasoning_item_id.unwrap_or_else(RunItemId::new),
            _ => RunItemId::new(),
        }
    }

    fn activity_record(&self, item_id: RunItemId, activity: &PendingRunActivity) -> RunItemRecord {
        let item = self.activity_item(activity);
        let mut record = RunItemRecord::new(item_id, RunItemSource::Runtime, item);
        record.call_id = self.call_id;
        record.task_id = self.task_id;
        record.parent_item_id = current_parent_step()
            .or(self.parent_item_id)
            .or(self.call_item_id);
        record.attempt_id = self.attempt_id;
        record.phase = self.phase;
        record
    }

    fn activity_item(&self, activity: &PendingRunActivity) -> RunItemV1 {
        match (activity.kind.as_str(), self.call_id) {
            ("tool-progress", Some(_)) => RunItemV1::ToolCallProgress {
                message: SafeText::condensed_line(&activity.label),
                completed: activity.completed,
                total: activity.total,
            },
            ("reasoning", Some(_)) => RunItemV1::SafeReasoningSummary {
                text: SafeText::condensed_line(&activity.label),
                redaction_policy_version: crate::run_lifecycle::RUN_ITEM_REDACTION_POLICY_VERSION,
            },
            _ => RunItemV1::DiagnosticNotice {
                level: diagnostic_level(activity),
                message: SafeText::condensed_line(&diagnostic_message(self, activity)),
            },
        }
    }
}

struct PendingRunActivity {
    kind: String,
    verb: String,
    label: String,
    severity: Option<String>,
    completed: Option<u64>,
    total: Option<u64>,
}

pub struct RunActivityBuilder<'a> {
    handle: &'a TraceHandle,
    pending: Option<PendingRunActivity>,
}

impl RunActivityBuilder<'_> {
    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        if let Some(pending) = self.pending.as_mut() {
            pending.severity = Some(severity.into());
        }
        self
    }

    pub fn with_progress(mut self, completed: u64, total: u64) -> Self {
        if let Some(pending) = self.pending.as_mut() {
            pending.completed = Some(completed);
            pending.total = Some(total);
        }
        self
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        if let Some(pending) = self.pending.as_mut() {
            pending.label = label.into();
        }
        self
    }

    pub fn emit(mut self) -> RunItemId {
        self.emit_pending()
    }

    fn emit_pending(&mut self) -> RunItemId {
        self.pending.take().map_or_else(RunItemId::new, |pending| {
            self.handle.record_activity(pending)
        })
    }
}

impl Drop for RunActivityBuilder<'_> {
    fn drop(&mut self) {
        if self.pending.is_some() {
            self.emit_pending();
        }
    }
}

fn diagnostic_level(activity: &PendingRunActivity) -> DiagnosticLevel {
    match activity.severity.as_deref() {
        Some("danger" | "error") => DiagnosticLevel::Error,
        Some("warn" | "warning") => DiagnosticLevel::Warning,
        _ if activity.kind == "refused" => DiagnosticLevel::Error,
        _ => DiagnosticLevel::Info,
    }
}

fn diagnostic_message(handle: &TraceHandle, activity: &PendingRunActivity) -> String {
    let owner = handle
        .module_id
        .as_deref()
        .filter(|module| !module.is_empty())
        .map(|module| format!("{module}:{}", activity.verb))
        .unwrap_or_else(|| activity.verb.clone());
    if owner.is_empty() || activity.label.starts_with(&owner) {
        activity.label.clone()
    } else {
        format!("{owner} · {}", activity.label)
    }
}

fn module_id_from_tool_name(name: &str) -> &str {
    name.split_once(':')
        .map(|(prefix, _)| prefix)
        .unwrap_or(name)
}
