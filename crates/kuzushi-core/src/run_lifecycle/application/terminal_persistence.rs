use crate::modules::ToolCallIdentity;
use crate::run_artifacts::load_run_summary;
use crate::run_lifecycle::{
    RunId, RunItemId, RunItemRecord, RunItemSource, RunItemStatus, RunItemV1, RunObservationHandle,
    SafeText, WorkflowContinuation,
};
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

#[path = "terminal_persistence/artifacts.rs"]
mod artifacts;
use artifacts::emit_artifact_references;
pub use artifacts::{verified_result_artifact_reference, verified_run_artifact_reference};

pub fn emit_persisted_terminal_outcome(
    observation: &RunObservationHandle,
    target: &Path,
    run_id: &str,
    output: &Value,
) -> Result<()> {
    emit_persisted_terminal_outcome_for_call(observation, target, run_id, output, None)
}

pub fn emit_persisted_terminal_outcome_for_call(
    observation: &RunObservationHandle,
    target: &Path,
    run_id: &str,
    output: &Value,
    producing_call: Option<ToolCallIdentity>,
) -> Result<()> {
    if crate::run_lifecycle::load_run_projection(target, run_id)?
        .projection
        .terminal
        .is_some()
    {
        return Ok(());
    }
    let summary = load_run_summary(target, run_id)?;
    let terminal_item_id = RunItemId::new();
    if let Some(identity) = producing_call {
        emit_artifact_references(observation, target, run_id, &summary.artifacts, identity)?;
    }
    terminalize_semantic_task(observation, target, run_id, &summary.status, producing_call)?;
    terminalize_semantic_plan(
        observation,
        target,
        run_id,
        lifecycle_status(&summary.status)?,
    )?;
    observation.emit_and_flush(RunItemRecord::new(
        terminal_item_id,
        RunItemSource::Workflow,
        terminal_item(target, run_id, output)?,
    ))?;
    Ok(())
}

pub fn emit_result_persistence_failure(
    observation: &RunObservationHandle,
    target: &Path,
    run_id: &str,
    identity: ToolCallIdentity,
    detail: &str,
    cost: crate::runtime::RuntimeCostReport,
    execution_status: RunItemStatus,
    execution_may_have_occurred: bool,
) -> Result<()> {
    let terminal_status = persistence_failure_status(execution_status, execution_may_have_occurred);
    let task_detail = persistence_failure_task_detail(execution_may_have_occurred);
    if observation
        .task_handle()
        .is_some_and(|task| task.task_id() == identity.task_id)
    {
        observation
            .task_handle()
            .expect("matching task checked above")
            .update_and_flush(terminal_status, Some(task_detail))?;
    } else {
        terminalize_task_by_identity(observation, target, run_id, identity, terminal_status)?;
    }
    terminalize_semantic_plan(observation, target, run_id, terminal_status)?;
    observation.emit_and_flush(RunItemRecord::new(
        RunItemId::new(),
        RunItemSource::Workflow,
        RunItemV1::TerminalOutcome {
            status: terminal_status,
            summary: persistence_failure_summary(detail, execution_may_have_occurred),
            cost,
            continuation: WorkflowContinuation::InspectRun {
                run_id: RunId::parse(run_id)?,
                reason: persistence_failure_continuation(execution_may_have_occurred),
            },
        },
    ))?;
    Ok(())
}

fn terminalize_semantic_plan(
    observation: &RunObservationHandle,
    target: &Path,
    run_id: &str,
    status: RunItemStatus,
) -> Result<()> {
    let projection = crate::run_lifecycle::load_run_projection(target, run_id)?.projection;
    let Some(plan) = projection.plan else {
        return Ok(());
    };
    if plan.status.is_terminal() {
        return Ok(());
    }
    observation.emit_and_flush(RunItemRecord::new(
        plan.item_id,
        RunItemSource::Workflow,
        RunItemV1::PlanUpdated {
            revision: plan.revision.saturating_add(1),
            title: plan.title,
            status,
            task_ids: plan.task_ids,
        },
    ))?;
    Ok(())
}

fn persistence_failure_status(
    execution_status: RunItemStatus,
    execution_may_have_occurred: bool,
) -> RunItemStatus {
    if execution_status == RunItemStatus::Failed || !execution_may_have_occurred {
        RunItemStatus::Failed
    } else {
        RunItemStatus::Partial
    }
}

fn persistence_failure_task_detail(execution_may_have_occurred: bool) -> &'static str {
    if execution_may_have_occurred {
        "execution finished, but durable result settlement failed"
    } else {
        "execution was refused before durable result settlement failed"
    }
}

fn persistence_failure_summary(detail: &str, execution_may_have_occurred: bool) -> SafeText {
    let timing = if execution_may_have_occurred {
        "after execution"
    } else {
        "before execution"
    };
    SafeText::operator_visible(format!("result persistence failed {timing}: {detail}"))
}

fn persistence_failure_continuation(execution_may_have_occurred: bool) -> SafeText {
    let reason = if execution_may_have_occurred {
        "inspect the incomplete run; side effects may have occurred and automatic retry is unsafe"
    } else {
        "inspect the failed run; execution was refused and no automatic retry was attempted"
    };
    SafeText::operator_visible(reason)
}

fn terminalize_task_by_identity(
    observation: &RunObservationHandle,
    target: &Path,
    run_id: &str,
    identity: ToolCallIdentity,
    status: RunItemStatus,
) -> Result<()> {
    let projection = crate::run_lifecycle::load_run_projection(target, run_id)?.projection;
    let task = projection
        .tasks
        .get(&identity.task_id)
        .ok_or_else(|| anyhow::anyhow!("producing call references an unknown semantic task"))?;
    if task.status.is_terminal() {
        return Ok(());
    }
    observation.emit_and_flush(
        RunItemRecord::new(
            task.item_id,
            RunItemSource::Workflow,
            RunItemV1::TaskUpdated {
                title: task.title.clone(),
                status,
                detail: Some(SafeText::operator_visible(
                    "durable result settlement failed",
                )),
            },
        )
        .with_task(identity.task_id),
    )?;
    Ok(())
}

fn terminalize_semantic_task(
    observation: &RunObservationHandle,
    target: &Path,
    run_id: &str,
    persisted_status: &str,
    producing_call: Option<ToolCallIdentity>,
) -> Result<()> {
    let projection = crate::run_lifecycle::load_run_projection(target, run_id)?.projection;
    if let Some(task) = observation.task_handle() {
        return terminalize_scoped_task(&projection, &task, persisted_status);
    }
    let Some(identity) = producing_call else {
        return Ok(());
    };
    let task = projection
        .tasks
        .get(&identity.task_id)
        .ok_or_else(|| anyhow::anyhow!("producing call references an unknown semantic task"))?;
    if task.status.is_terminal() {
        return Ok(());
    }
    emit_task_terminal(observation, task, identity.task_id, persisted_status)?;
    Ok(())
}

fn terminalize_scoped_task(
    projection: &crate::run_lifecycle::RunProjection,
    task: &crate::run_lifecycle::RunTaskHandle,
    persisted_status: &str,
) -> Result<()> {
    let already_terminal = projection
        .tasks
        .get(&task.task_id())
        .is_some_and(|projected| projected.status.is_terminal());
    if !already_terminal {
        task.update_and_flush(lifecycle_status(persisted_status)?, None)?;
    }
    Ok(())
}

fn emit_task_terminal(
    observation: &RunObservationHandle,
    task: &crate::run_lifecycle::TaskProjection,
    task_id: crate::run_lifecycle::RunTaskId,
    persisted_status: &str,
) -> Result<()> {
    observation.emit_and_flush(
        RunItemRecord::new(
            task.item_id,
            RunItemSource::Workflow,
            RunItemV1::TaskUpdated {
                title: task.title.clone(),
                status: lifecycle_status(persisted_status)?,
                detail: None,
            },
        )
        .with_task(task_id),
    )?;
    Ok(())
}

fn terminal_item(target: &Path, run_id: &str, output: &Value) -> Result<RunItemV1> {
    let persisted = crate::run_artifacts::load_run_summary(target, run_id)?;
    let status = lifecycle_status(&persisted.status)?;
    let cost = persisted.checked_cost_report()?;
    let summary = output
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or("tool run finished");
    Ok(RunItemV1::TerminalOutcome {
        status,
        summary: SafeText::operator_visible(summary),
        cost,
        continuation: terminal_continuation(run_id, status)?,
    })
}

fn terminal_continuation(run_id: &str, status: RunItemStatus) -> Result<WorkflowContinuation> {
    if matches!(status, RunItemStatus::Partial | RunItemStatus::Failed) {
        return Ok(WorkflowContinuation::InspectRun {
            run_id: RunId::parse(run_id)?,
            reason: SafeText::operator_visible("inspect the incomplete or failed run evidence"),
        });
    }
    Ok(WorkflowContinuation::NoFurtherAction {
        reason: SafeText::operator_visible("no phase continuation is attached to this run"),
    })
}

fn lifecycle_status(status: &str) -> Result<RunItemStatus> {
    match status {
        "completed" => Ok(RunItemStatus::Completed),
        "partial" => Ok(RunItemStatus::Partial),
        "skipped" => Ok(RunItemStatus::Skipped),
        "failed" => Ok(RunItemStatus::Failed),
        "canceled" => Ok(RunItemStatus::Canceled),
        "interrupted" => Ok(RunItemStatus::Interrupted),
        other => anyhow::bail!("run {other:?} is not terminal"),
    }
}
