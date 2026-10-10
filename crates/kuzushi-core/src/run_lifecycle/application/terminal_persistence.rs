use crate::modules::ToolCallIdentity;
use crate::run_lifecycle::{
    CallKind, ModelUsage, RunCallId, RunId, RunItemId, RunItemRecord, RunItemSource, RunItemStatus,
    RunItemV1, RunObservationHandle, RunProjection, SafeText, WorkflowContinuation,
};
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

#[path = "terminal_persistence/artifacts.rs"]
mod artifacts;
use artifacts::emit_artifact_references;
pub use artifacts::{verified_result_artifact_reference, verified_run_artifact_reference};

pub(crate) fn emit_recovered_interruption(
    target: &Path,
    run_id: &str,
    reason: &str,
    cost: crate::runtime::RuntimeCostReport,
) -> Result<()> {
    let projection = crate::run_lifecycle::load_run_projection_unhydrated(target, run_id)?;
    if projection.terminal.is_some() {
        return Ok(());
    }
    let observation = RunObservationHandle::jsonl(target.to_path_buf(), run_id.to_string())?;
    interrupt_open_calls(&observation, &projection, target, run_id)?;
    interrupt_open_tasks(&observation, &projection, reason)?;
    interrupt_open_plan(&observation, &projection)?;
    observation.emit_and_flush(RunItemRecord::new(
        RunItemId::new(),
        RunItemSource::Persistence,
        RunItemV1::TerminalOutcome {
            status: RunItemStatus::Interrupted,
            summary: SafeText::operator_visible(reason),
            cost,
            continuation: WorkflowContinuation::InspectRun {
                run_id: RunId::parse(run_id)?,
                reason: SafeText::operator_visible("inspect the interrupted run evidence"),
            },
        },
    ))?;
    observation.flush()
}

fn interrupt_open_calls(
    observation: &RunObservationHandle,
    projection: &RunProjection,
    target: &Path,
    run_id: &str,
) -> Result<()> {
    for call_id in &projection.call_order {
        let call = &projection.calls[call_id];
        if call.status.is_terminal() {
            continue;
        }
        let result = recovered_root_result_reference(target, run_id, call)?;
        observation.emit_and_flush(interrupted_call_record(*call_id, call, result)?)?;
    }
    Ok(())
}

fn interrupted_call_record(
    call_id: RunCallId,
    call: &crate::run_lifecycle::CallProjection,
    result: Option<crate::run_lifecycle::ArtifactReference>,
) -> Result<RunItemRecord> {
    let item = match (call.kind, call.status) {
        (CallKind::Tool, RunItemStatus::Pending) => RunItemV1::ToolCallRejected {
            reason_class: SafeText::operator_visible("process_interrupted"),
            detail: SafeText::operator_visible("execution stopped before the tool started"),
        },
        (CallKind::Tool, _) => interrupted_tool_finish(result),
        (CallKind::Model, _) => interrupted_model_finish(call),
    };
    Ok(scope_call_record(
        RunItemRecord::new(call.item_id, RunItemSource::Persistence, item),
        call_id,
        call,
    ))
}

fn recovered_root_result_reference(
    target: &Path,
    run_id: &str,
    call: &crate::run_lifecycle::CallProjection,
) -> Result<Option<crate::run_lifecycle::ArtifactReference>> {
    if call.kind != CallKind::Tool
        || call.parent_item_id.is_some()
        || call.status == RunItemStatus::Pending
    {
        return Ok(None);
    }
    // The host's recovered result belongs only to the root call. Nested
    // engines retain missing results; no engine membership is reconstructed.
    verified_result_artifact_reference(target, run_id, call.item_id).map(Some)
}

fn interrupted_tool_finish(result: Option<crate::run_lifecycle::ArtifactReference>) -> RunItemV1 {
    RunItemV1::ToolCallFinished {
        status: RunItemStatus::Interrupted,
        cost: crate::runtime::RuntimeCostReport::UNAVAILABLE,
        result_artifact: result,
        preview: vec![SafeText::operator_visible("tool execution was interrupted")],
        warning_count: 0,
        error_count: 1,
    }
}

fn interrupted_model_finish(call: &crate::run_lifecycle::CallProjection) -> RunItemV1 {
    RunItemV1::ModelCallFinished {
        provider: call
            .provider
            .clone()
            .unwrap_or_else(|| SafeText::operator_visible("unknown")),
        model: call.model.clone().unwrap_or_else(|| call.label.clone()),
        status: RunItemStatus::Interrupted,
        latency_ms: elapsed_call_ms(call),
        usage: ModelUsage {
            input_tokens: None,
            output_tokens: None,
        },
        cost: crate::runtime::RuntimeCostReport::UNAVAILABLE,
        error_class: Some(SafeText::operator_visible("process_interrupted")),
        failure: None,
    }
}

fn elapsed_call_ms(call: &crate::run_lifecycle::CallProjection) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    now.saturating_sub(call.started_at_ms.unwrap_or(now))
}

fn scope_call_record(
    mut record: RunItemRecord,
    call_id: RunCallId,
    call: &crate::run_lifecycle::CallProjection,
) -> RunItemRecord {
    record = record.with_call(call_id);
    if let Some(task_id) = call.task_id {
        record = record.with_task(task_id);
    }
    if let Some(parent_item_id) = call.parent_item_id {
        record = record.with_parent(parent_item_id);
    }
    record
}

fn interrupt_open_tasks(
    observation: &RunObservationHandle,
    projection: &RunProjection,
    reason: &str,
) -> Result<()> {
    for task_id in &projection.task_order {
        let task = &projection.tasks[task_id];
        if task.status.is_terminal() {
            continue;
        }
        observation.emit_and_flush(
            RunItemRecord::new(
                task.item_id,
                RunItemSource::Persistence,
                RunItemV1::TaskUpdated {
                    title: task.title.clone(),
                    status: RunItemStatus::Interrupted,
                    detail: Some(SafeText::operator_visible(reason)),
                },
            )
            .with_task(*task_id),
        )?;
    }
    Ok(())
}

fn interrupt_open_plan(
    observation: &RunObservationHandle,
    projection: &RunProjection,
) -> Result<()> {
    let Some(plan) = projection
        .plan
        .as_ref()
        .filter(|plan| !plan.status.is_terminal())
    else {
        return Ok(());
    };
    observation.emit_and_flush(RunItemRecord::new(
        plan.item_id,
        RunItemSource::Persistence,
        RunItemV1::PlanUpdated {
            revision: plan.revision.saturating_add(1),
            title: plan.title.clone(),
            status: RunItemStatus::Interrupted,
            task_ids: plan.task_ids.clone(),
        },
    ))?;
    Ok(())
}

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
    let summary = crate::run_artifacts::load_run_summary_without_repair(target, run_id)?;
    emit_terminal_outcome_for_summary(
        observation,
        target,
        run_id,
        output,
        &summary,
        producing_call,
    )
}

pub(crate) fn emit_terminal_outcome_for_summary(
    observation: &RunObservationHandle,
    target: &Path,
    run_id: &str,
    output: &Value,
    summary: &crate::run_artifacts::RunSummary,
    producing_call: Option<ToolCallIdentity>,
) -> Result<()> {
    if crate::run_lifecycle::load_run_projection_unhydrated(target, run_id)?
        .terminal
        .is_some()
    {
        return Ok(());
    }
    let status = terminal_status_for_call(target, run_id, &summary.status, producing_call)?;
    let terminal_item_id = RunItemId::new();
    if let Some(identity) = producing_call {
        emit_artifact_references(observation, target, run_id, &summary.artifacts, identity)?;
    }
    terminalize_semantic_task(observation, target, run_id, status, producing_call)?;
    terminalize_semantic_plan(observation, target, run_id, status)?;
    observation.emit_and_flush(RunItemRecord::new(
        terminal_item_id,
        RunItemSource::Workflow,
        terminal_item(summary, run_id, output, status)?,
    ))?;
    record_coverage_baseline(target, summary);
    Ok(())
}

/// Coverage is derived truth written only after the terminal receipt exists;
/// a ledger write failure must not fail the terminal event itself.
fn record_coverage_baseline(target: &Path, summary: &crate::run_artifacts::RunSummary) {
    if let Err(error) =
        crate::workspace::coverage_ledger::record_baseline_from_summary(target, summary)
    {
        crate::runtime_diagnostics::record_runtime_diagnostic(
            "coverage",
            format!(
                "coverage baseline not recorded for run {}: {error:#}",
                summary.run_id
            ),
        );
    }
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
        .is_some_and(|task| Some(task.task_id()) == identity.task_id)
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
    let projection = crate::run_lifecycle::load_run_projection_unhydrated(target, run_id)?;
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
    let Some(task_id) = identity.task_id else {
        return Ok(());
    };
    let projection = crate::run_lifecycle::load_run_projection_unhydrated(target, run_id)?;
    let task = projection
        .tasks
        .get(&task_id)
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
        .with_task(task_id),
    )?;
    Ok(())
}

fn terminalize_semantic_task(
    observation: &RunObservationHandle,
    target: &Path,
    run_id: &str,
    status: RunItemStatus,
    producing_call: Option<ToolCallIdentity>,
) -> Result<()> {
    let projection = crate::run_lifecycle::load_run_projection_unhydrated(target, run_id)?;
    if let Some(task) = observation.task_handle() {
        return terminalize_scoped_task(&projection, &task, status);
    }
    let Some(identity) = producing_call else {
        return Ok(());
    };
    let Some(task_id) = identity.task_id else {
        return Ok(());
    };
    let task = projection
        .tasks
        .get(&task_id)
        .ok_or_else(|| anyhow::anyhow!("producing call references an unknown semantic task"))?;
    if task.status.is_terminal() {
        return Ok(());
    }
    emit_task_terminal(observation, task, task_id, status)?;
    Ok(())
}

fn terminalize_scoped_task(
    projection: &crate::run_lifecycle::RunProjection,
    task: &crate::run_lifecycle::RunTaskHandle,
    status: RunItemStatus,
) -> Result<()> {
    let already_terminal = projection
        .tasks
        .get(&task.task_id())
        .is_some_and(|projected| projected.status.is_terminal());
    if !already_terminal {
        task.update_and_flush(status, None)?;
    }
    Ok(())
}

fn emit_task_terminal(
    observation: &RunObservationHandle,
    task: &crate::run_lifecycle::TaskProjection,
    task_id: crate::run_lifecycle::RunTaskId,
    status: RunItemStatus,
) -> Result<()> {
    observation.emit_and_flush(
        RunItemRecord::new(
            task.item_id,
            RunItemSource::Workflow,
            RunItemV1::TaskUpdated {
                title: task.title.clone(),
                status,
                detail: None,
            },
        )
        .with_task(task_id),
    )?;
    Ok(())
}

fn terminal_item(
    persisted: &crate::run_artifacts::RunSummary,
    run_id: &str,
    output: &Value,
    status: RunItemStatus,
) -> Result<RunItemV1> {
    let cost = persisted.checked_cost_report()?;
    let summary = output
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or("tool run finished");
    Ok(RunItemV1::TerminalOutcome {
        status,
        summary: SafeText::condensed_line(summary),
        cost,
        continuation: terminal_continuation(run_id, status)?,
    })
}

fn terminal_continuation(run_id: &str, status: RunItemStatus) -> Result<WorkflowContinuation> {
    if matches!(
        status,
        RunItemStatus::Partial | RunItemStatus::Blocked | RunItemStatus::Failed
    ) {
        return Ok(WorkflowContinuation::InspectRun {
            run_id: RunId::parse(run_id)?,
            reason: SafeText::operator_visible("inspect the incomplete or failed run evidence"),
        });
    }
    Ok(WorkflowContinuation::NoFurtherAction {
        reason: SafeText::operator_visible("no phase continuation is attached to this run"),
    })
}

fn terminal_status_for_call(
    target: &Path,
    run_id: &str,
    persisted_status: &str,
    producing_call: Option<ToolCallIdentity>,
) -> Result<RunItemStatus> {
    let persisted = lifecycle_status(persisted_status)?;
    let Some(identity) = producing_call else {
        return Ok(persisted);
    };
    let projection = crate::run_lifecycle::load_run_projection_unhydrated(target, run_id)?;
    Ok(projection
        .calls
        .get(&identity.call_id)
        .filter(|call| call.item_id == identity.item_id && call.status.is_terminal())
        .map_or(persisted, |call| call.status))
}

fn lifecycle_status(status: &str) -> Result<RunItemStatus> {
    match status {
        "completed" => Ok(RunItemStatus::Completed),
        "partial" => Ok(RunItemStatus::Partial),
        "skipped" => Ok(RunItemStatus::Skipped),
        "blocked" => Ok(RunItemStatus::Blocked),
        "failed" => Ok(RunItemStatus::Failed),
        "canceled" => Ok(RunItemStatus::Canceled),
        "interrupted" => Ok(RunItemStatus::Interrupted),
        other => anyhow::bail!("run {other:?} is not terminal"),
    }
}
