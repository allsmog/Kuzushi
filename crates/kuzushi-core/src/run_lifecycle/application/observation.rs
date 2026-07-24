use crate::run_artifacts::TraceHandle;
use crate::run_lifecycle::{RunAttemptId, RunItemEnvelopeV1, RunItemId, RunItemRecord, RunTaskId};
use crate::WorkflowPhase;
use anyhow::{Context, Result};

#[path = "observation/task_handles.rs"]
mod task_handles;
pub use task_handles::{ObservedRunTask, RunPlanHandle, RunTaskHandle};

#[path = "observation/open.rs"]
mod open;

#[path = "observation/plan_scope.rs"]
mod plan_scope;

#[derive(Clone)]
pub struct RunObservationHandle {
    trace: TraceHandle,
    plan_item_id: Option<RunItemId>,
    plan_revision: u64,
    task_id: Option<RunTaskId>,
    task_item_id: Option<RunItemId>,
    task_title: Option<String>,
    parent_item_id: Option<RunItemId>,
    attempt_id: Option<RunAttemptId>,
    phase: Option<WorkflowPhase>,
}

impl RunObservationHandle {
    pub fn trace_handle(&self) -> TraceHandle {
        self.trace.with_run_item_scope(
            self.plan_item_id,
            self.plan_revision,
            self.task_id,
            self.task_item_id,
            self.task_title.clone(),
            self.parent_item_id,
            self.attempt_id,
            self.phase,
        )
    }

    pub fn for_task(&self, task_id: RunTaskId) -> Self {
        let mut scoped = self.clone();
        scoped.task_id = Some(task_id);
        if scoped.task_id != self.task_id {
            scoped.task_item_id = None;
            scoped.task_title = None;
        }
        scoped
    }

    pub fn task_id(&self) -> Option<RunTaskId> {
        self.task_id
    }

    pub fn task_handle(&self) -> Option<RunTaskHandle> {
        Some(ObservedRunTask {
            observation: self.clone(),
            task_id: self.task_id?,
            item_id: self.task_item_id?,
            title: self.task_title.clone()?,
        })
    }

    /// Every dispatch inherits the workflow-owned semantic task. Nested
    /// dispatches distinguish their work through call parentage instead of
    /// inventing presentation-only task rows.
    pub(crate) fn inheritable_dispatch_task_id(&self) -> Option<RunTaskId> {
        self.task_id
    }

    pub fn with_parent(&self, parent_item_id: RunItemId) -> Self {
        let mut scoped = self.clone();
        scoped.parent_item_id = Some(parent_item_id);
        scoped
    }

    pub(crate) fn for_call_progress(
        &self,
        call_id: crate::run_lifecycle::RunCallId,
        item_id: RunItemId,
    ) -> Self {
        let mut scoped = self.clone();
        scoped.trace = scoped
            .trace
            .with_run_call_scope(call_id, item_id, self.parent_item_id);
        scoped
    }

    pub(crate) fn parent_item_id(&self) -> Option<RunItemId> {
        self.parent_item_id
    }

    pub(crate) fn with_plan_scope(mut self, plan_item_id: RunItemId, plan_revision: u64) -> Self {
        self.plan_item_id = Some(plan_item_id);
        self.plan_revision = plan_revision;
        self
    }

    pub(crate) fn with_task_scope(mut self, item_id: RunItemId, title: &str) -> Self {
        self.task_item_id = Some(item_id);
        self.task_title = Some(title.to_string());
        self
    }

    fn without_work_scope(mut self) -> Self {
        self.task_id = None;
        self.task_item_id = None;
        self.task_title = None;
        self.parent_item_id = None;
        self
    }

    pub fn for_attempt(&self, attempt_id: RunAttemptId, phase: WorkflowPhase) -> Self {
        let mut scoped = self.clone();
        scoped.attempt_id = Some(attempt_id);
        scoped.phase = Some(phase);
        scoped
    }

    pub fn emit(&self, record: RunItemRecord) -> Result<()> {
        self.writer()?.emit(self.scope(record))
    }

    pub fn emit_coalescible(&self, record: RunItemRecord) -> Result<()> {
        self.writer()?.emit_coalescible(self.scope(record))
    }

    pub fn emit_and_flush(&self, record: RunItemRecord) -> Result<RunItemEnvelopeV1> {
        self.writer()?.emit_and_flush(self.scope(record))
    }

    pub fn flush(&self) -> Result<()> {
        self.writer()?.flush()
    }

    fn scope(&self, mut record: RunItemRecord) -> RunItemRecord {
        record.task_id = record.task_id.or(self.task_id);
        record.parent_item_id = record.parent_item_id.or(self.parent_item_id);
        record.attempt_id = record.attempt_id.or(self.attempt_id);
        record.phase = record.phase.or(self.phase);
        record
    }

    fn writer(&self) -> Result<&crate::run_lifecycle::RunItemWriter> {
        self.trace
            .item_writer()
            .context("trace handle has no typed run-item sink")
    }
}
