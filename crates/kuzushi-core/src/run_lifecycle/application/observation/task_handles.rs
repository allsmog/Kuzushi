use super::RunObservationHandle;
use crate::run_lifecycle::{
    RunItemEnvelopeV1, RunItemId, RunItemRecord, RunItemSource, RunItemStatus, RunItemV1,
    RunTaskId, SafeText,
};
use anyhow::Result;

#[derive(Clone)]
pub struct ObservedRunTask {
    pub(super) observation: RunObservationHandle,
    pub(super) task_id: RunTaskId,
    pub(super) item_id: RunItemId,
    pub(super) title: String,
}

pub type RunTaskHandle = ObservedRunTask;

pub struct RunPlanHandle {
    pub(super) observation: RunObservationHandle,
    pub(super) item_id: RunItemId,
    pub(super) title: String,
    pub(super) revision: u64,
    pub(super) tasks: Vec<RunTaskHandle>,
}

impl RunPlanHandle {
    pub fn observation(&self) -> &RunObservationHandle {
        &self.observation
    }

    pub fn tasks(&self) -> &[RunTaskHandle] {
        &self.tasks
    }

    /// Extend an application-owned plan with real semantic work while
    /// preserving every previously declared task and its first-seen order.
    pub fn extend_tasks(
        &mut self,
        task_titles: impl IntoIterator<Item = String>,
    ) -> Result<Vec<RunTaskHandle>> {
        let added = task_titles
            .into_iter()
            .map(|title| ObservedRunTask::new(self.observation.clone(), title))
            .collect::<Vec<_>>();
        if added.is_empty() {
            return Ok(Vec::new());
        }
        let revision = self.revision.saturating_add(1);
        let mut task_ids = self
            .tasks
            .iter()
            .map(ObservedRunTask::task_id)
            .collect::<Vec<_>>();
        task_ids.extend(added.iter().map(ObservedRunTask::task_id));
        self.observation.emit(RunItemRecord::new(
            self.item_id,
            RunItemSource::Workflow,
            RunItemV1::PlanUpdated {
                revision,
                title: SafeText::operator_visible(&self.title),
                status: RunItemStatus::Running,
                task_ids,
            },
        ))?;
        for task in &added {
            task.update(RunItemStatus::Pending, None)?;
        }
        self.observation.writer()?.flush()?;
        self.revision = revision;
        self.tasks.extend(added.iter().cloned());
        Ok(added)
    }

    pub fn update(&mut self, status: RunItemStatus) -> Result<()> {
        let revision = self.revision.saturating_add(1);
        self.observation
            .emit(self.update_record(revision, status))?;
        self.revision = revision;
        Ok(())
    }

    pub fn update_and_flush(&mut self, status: RunItemStatus) -> Result<RunItemEnvelopeV1> {
        let revision = self.revision.saturating_add(1);
        let envelope = self
            .observation
            .emit_and_flush(self.update_record(revision, status))?;
        self.revision = revision;
        Ok(envelope)
    }

    fn update_record(&self, revision: u64, status: RunItemStatus) -> RunItemRecord {
        RunItemRecord::new(
            self.item_id,
            RunItemSource::Workflow,
            RunItemV1::PlanUpdated {
                revision,
                title: SafeText::operator_visible(&self.title),
                status,
                task_ids: self.tasks.iter().map(ObservedRunTask::task_id).collect(),
            },
        )
    }
}

impl ObservedRunTask {
    pub(super) fn new(observation: RunObservationHandle, title: String) -> Self {
        Self::with_id(observation, RunTaskId::new(), title)
    }

    pub(super) fn with_id(
        observation: RunObservationHandle,
        task_id: RunTaskId,
        title: String,
    ) -> Self {
        Self {
            observation,
            task_id,
            item_id: RunItemId::new(),
            title,
        }
    }

    pub fn task_id(&self) -> RunTaskId {
        self.task_id
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn update(&self, status: RunItemStatus, detail: Option<&str>) -> Result<()> {
        self.observation.emit(self.update_record(status, detail))
    }

    pub fn update_and_flush(
        &self,
        status: RunItemStatus,
        detail: Option<&str>,
    ) -> Result<RunItemEnvelopeV1> {
        self.observation
            .emit_and_flush(self.update_record(status, detail))
    }

    pub fn observation(&self) -> RunObservationHandle {
        let mut observation = self.observation.for_task(self.task_id);
        observation.task_item_id = Some(self.item_id);
        observation.task_title = Some(self.title.clone());
        observation
    }

    fn update_record(&self, status: RunItemStatus, detail: Option<&str>) -> RunItemRecord {
        RunItemRecord::new(
            self.item_id,
            RunItemSource::Workflow,
            RunItemV1::TaskUpdated {
                title: SafeText::operator_visible(&self.title),
                status,
                detail: detail.map(SafeText::operator_visible),
            },
        )
        .with_task(self.task_id)
    }
}
