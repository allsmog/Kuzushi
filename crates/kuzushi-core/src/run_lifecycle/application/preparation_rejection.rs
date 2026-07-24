use crate::run_lifecycle::{
    RunItemId, RunItemRecord, RunItemSource, RunItemStatus, RunItemV1, RunObservationHandle,
    SafeText, WorkflowContinuation,
};
use crate::runtime::RuntimeCostReport;
use anyhow::Result;
use serde_json::Value;

pub struct ObservedPreparationRejection {
    observation: RunObservationHandle,
    completion: crate::modules::PendingToolCallCompletion,
}

impl ObservedPreparationRejection {
    pub fn into_parts(
        self,
    ) -> (
        RunObservationHandle,
        crate::modules::PendingToolCallCompletion,
    ) {
        (self.observation, self.completion)
    }
}

pub fn observe_preparation_rejection(
    observation: &RunObservationHandle,
    tool_name: &str,
    input: &Value,
    reason_class: &str,
    detail: &str,
) -> Result<ObservedPreparationRejection> {
    let (scoped, _) = rejection_scope(observation, tool_name)?;
    let completion = crate::modules::ApplicationToolCall::reject_before_start(
        scoped.clone(),
        tool_name,
        input,
        reason_class,
        detail,
    )?;
    Ok(ObservedPreparationRejection {
        observation: scoped,
        completion,
    })
}

pub fn emit_preparation_rejection(
    observation: &RunObservationHandle,
    tool_name: &str,
    input: &Value,
    reason_class: &str,
    detail: &str,
) -> Result<RunObservationHandle> {
    let (scoped, mut created_plan) = rejection_scope(observation, tool_name)?;
    let completion = crate::modules::ApplicationToolCall::reject_before_start(
        scoped.clone(),
        tool_name,
        input,
        reason_class,
        detail,
    )?;
    completion.finish(None)?;
    let task = scoped
        .task_handle()
        .ok_or_else(|| anyhow::anyhow!("preparation rejection lacks a semantic task"))?;
    task.update_and_flush(
        RunItemStatus::Blocked,
        Some("request rejected before tool execution"),
    )?;
    if let Some(plan) = created_plan.as_mut() {
        plan.update_and_flush(RunItemStatus::Blocked)?;
    }
    scoped.emit_and_flush(RunItemRecord::new(
        RunItemId::new(),
        RunItemSource::Workflow,
        RunItemV1::TerminalOutcome {
            status: RunItemStatus::Blocked,
            summary: SafeText::condensed_line(detail),
            cost: RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO),
            continuation: WorkflowContinuation::NoFurtherAction {
                reason: SafeText::operator_visible("correct the rejected request before retrying"),
            },
        },
    ))?;
    Ok(scoped)
}

fn rejection_scope(
    observation: &RunObservationHandle,
    tool_name: &str,
) -> Result<(
    RunObservationHandle,
    Option<crate::run_lifecycle::RunPlanHandle>,
)> {
    if observation.task_handle().is_some() {
        return Ok((observation.clone(), None));
    }
    let title = format!("Prepare {tool_name}");
    let plan = observation.start_plan(&title, [title.clone()])?;
    let scoped = plan.tasks()[0].observation();
    Ok((scoped, Some(plan)))
}
