//! Close stopped calls and semantic work without claiming a provider settlement.
use super::*;

pub(super) fn stop_open_activity(
    observation: &RunObservationHandle,
    projection: &RunProjection,
    target: &Path,
    run_id: &str,
    reason: &str,
    status: RunItemStatus,
) -> Result<()> {
    stop_open_calls(observation, projection, target, run_id, status)?;
    stop_open_tasks(observation, projection, reason, status)?;
    stop_open_plan(observation, projection, status)
}

fn stop_class(status: RunItemStatus) -> &'static str {
    match status {
        RunItemStatus::Canceled => "operator_canceled",
        _ => "process_interrupted",
    }
}

fn stop_open_calls(
    observation: &RunObservationHandle,
    projection: &RunProjection,
    target: &Path,
    run_id: &str,
    status: RunItemStatus,
) -> Result<()> {
    for call_id in &projection.call_order {
        let call = &projection.calls[call_id];
        if call.status.is_terminal() {
            continue;
        }
        let result = recovered_root_result_reference(target, run_id, call)?;
        observation.emit_and_flush(stopped_call_record(*call_id, call, result, status)?)?;
    }
    Ok(())
}

fn stopped_call_record(
    call_id: RunCallId,
    call: &crate::run_lifecycle::CallProjection,
    result: Option<crate::run_lifecycle::ArtifactReference>,
    status: RunItemStatus,
) -> Result<RunItemRecord> {
    let item = match (call.kind, call.status) {
        (CallKind::Tool, RunItemStatus::Pending) => RunItemV1::ToolCallRejected {
            reason_class: SafeText::operator_visible(stop_class(status)),
            detail: SafeText::operator_visible("execution stopped before the tool started"),
        },
        (CallKind::Tool, _) => stopped_tool_finish(result, status),
        (CallKind::Model, _) => stopped_model_finish(call, status),
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

fn stopped_tool_finish(
    result: Option<crate::run_lifecycle::ArtifactReference>,
    status: RunItemStatus,
) -> RunItemV1 {
    RunItemV1::ToolCallFinished {
        status,
        cost: crate::runtime::RuntimeCostReport::UNAVAILABLE,
        result_artifact: result,
        preview: vec![SafeText::operator_visible(
            "tool execution stopped before completion",
        )],
        warning_count: 0,
        error_count: 1,
    }
}

fn stopped_model_finish(
    call: &crate::run_lifecycle::CallProjection,
    status: RunItemStatus,
) -> RunItemV1 {
    RunItemV1::ModelCallFinished {
        provider: call
            .provider
            .clone()
            .unwrap_or_else(|| SafeText::operator_visible("unknown")),
        model: call.model.clone().unwrap_or_else(|| call.label.clone()),
        status,
        latency_ms: elapsed_call_ms(call),
        usage: ModelUsage {
            input_tokens: None,
            output_tokens: None,
        },
        cost: crate::runtime::RuntimeCostReport::UNAVAILABLE,
        error_class: Some(SafeText::operator_visible(stop_class(status))),
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

fn stop_open_tasks(
    observation: &RunObservationHandle,
    projection: &RunProjection,
    reason: &str,
    status: RunItemStatus,
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
                    status,
                    detail: Some(SafeText::operator_visible(reason)),
                },
            )
            .with_task(*task_id),
        )?;
    }
    Ok(())
}

fn stop_open_plan(
    observation: &RunObservationHandle,
    projection: &RunProjection,
    status: RunItemStatus,
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
            status,
            task_ids: plan.task_ids.clone(),
        },
    ))?;
    Ok(())
}
