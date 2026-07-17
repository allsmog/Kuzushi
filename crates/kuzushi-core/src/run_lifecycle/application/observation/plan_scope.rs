use super::{ObservedRunTask, RunObservationHandle, RunPlanHandle};
use crate::run_lifecycle::{
    RunItemId, RunItemRecord, RunItemSource, RunItemStatus, RunItemV1, RunTaskId, SafeText,
};
use anyhow::{Context, Result};

impl RunObservationHandle {
    pub fn start_root_task(&self, title: impl AsRef<str>) -> Result<Self> {
        self.start_root_task_with_id(RunTaskId::new(), title)
    }

    pub fn start_plan(
        &self,
        title: impl AsRef<str>,
        task_titles: impl IntoIterator<Item = String>,
    ) -> Result<RunPlanHandle> {
        let tasks = task_titles
            .into_iter()
            .map(|task_title| (RunTaskId::new(), task_title))
            .collect();
        self.start_plan_with_tasks(title.as_ref(), tasks)
    }

    pub fn start_root_task_with_id(
        &self,
        task_id: RunTaskId,
        title: impl AsRef<str>,
    ) -> Result<Self> {
        let title = title.as_ref().to_string();
        let plan = self.start_plan_with_tasks(&title, vec![(task_id, title.clone())])?;
        Ok(plan.tasks[0].observation())
    }

    pub fn start_plan_with_tasks(
        &self,
        title: &str,
        tasks: Vec<(RunTaskId, String)>,
    ) -> Result<RunPlanHandle> {
        anyhow::ensure!(
            !tasks.is_empty(),
            "run plan requires at least one semantic task"
        );
        let plan_item_id = RunItemId::new();
        self.emit(initial_plan_record(plan_item_id, title, &tasks))?;
        let observation = self.clone().with_plan_scope(plan_item_id, 1);
        let tasks = observed_tasks(&observation, tasks);
        initialize_tasks(&observation, &tasks)?;
        Ok(RunPlanHandle {
            observation,
            item_id: plan_item_id,
            title: title.to_string(),
            revision: 1,
            tasks,
        })
    }

    /// Rehydrate the application-owned plan handle from its durable typed
    /// projection after a scoped trace crosses an executor boundary.
    pub fn plan_handle(&self) -> Result<Option<RunPlanHandle>> {
        let Some(plan_item_id) = self.plan_item_id else {
            return Ok(None);
        };
        self.rehydrate_plan(plan_item_id)
    }

    fn rehydrate_plan(&self, plan_item_id: RunItemId) -> Result<Option<RunPlanHandle>> {
        let (target, run_id) = self
            .trace
            .run_artifact_location()
            .context("run observation has no durable artifact location")?;
        let projection = crate::run_lifecycle::load_run_projection(&target, &run_id)?.projection;
        let Some(ref plan) = projection.plan else {
            return Ok(None);
        };
        anyhow::ensure!(plan.item_id == plan_item_id, "run plan identity changed");
        let observation = self
            .clone()
            .without_work_scope()
            .with_plan_scope(plan.item_id, plan.revision);
        let tasks = rehydrated_tasks(&observation, &projection, &plan.task_ids)?;
        Ok(Some(RunPlanHandle {
            observation,
            item_id: plan.item_id,
            title: plan.title.as_str().to_string(),
            revision: plan.revision,
            tasks,
        }))
    }
}

fn initial_plan_record(
    item_id: RunItemId,
    title: &str,
    tasks: &[(RunTaskId, String)],
) -> RunItemRecord {
    RunItemRecord::new(
        item_id,
        RunItemSource::Workflow,
        RunItemV1::PlanUpdated {
            revision: 1,
            title: SafeText::operator_visible(title),
            status: RunItemStatus::Pending,
            task_ids: tasks.iter().map(|(task_id, _)| *task_id).collect(),
        },
    )
}

fn observed_tasks(
    observation: &RunObservationHandle,
    tasks: Vec<(RunTaskId, String)>,
) -> Vec<ObservedRunTask> {
    tasks
        .into_iter()
        .map(|(task_id, title)| ObservedRunTask::with_id(observation.clone(), task_id, title))
        .collect()
}

fn initialize_tasks(observation: &RunObservationHandle, tasks: &[ObservedRunTask]) -> Result<()> {
    for task in tasks {
        task.update(RunItemStatus::Pending, None)?;
    }
    observation.writer()?.flush()
}

fn rehydrated_tasks(
    observation: &RunObservationHandle,
    projection: &crate::run_lifecycle::RunProjection,
    task_ids: &[RunTaskId],
) -> Result<Vec<ObservedRunTask>> {
    task_ids
        .iter()
        .map(|task_id| rehydrated_task(observation, projection, *task_id))
        .collect()
}

fn rehydrated_task(
    observation: &RunObservationHandle,
    projection: &crate::run_lifecycle::RunProjection,
    task_id: RunTaskId,
) -> Result<ObservedRunTask> {
    let task = projection
        .tasks
        .get(&task_id)
        .context("run plan references an unavailable semantic task")?;
    Ok(ObservedRunTask {
        observation: observation.clone(),
        task_id,
        item_id: task.item_id,
        title: task.title.as_str().to_string(),
    })
}
