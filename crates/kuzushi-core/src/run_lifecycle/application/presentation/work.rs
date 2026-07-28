use super::call_details::CallDetails;
use super::*;

pub(super) fn work_cells(
    projection: &RunProjection,
    details: &BTreeMap<RunCallId, CallDetails>,
    quarantine: Option<&completion_quarantine::CompletionQuarantine>,
) -> Vec<RunPresentationCellV1> {
    let mut cells = Vec::new();
    append_plan_cell(&mut cells, projection, quarantine);
    let call_order = ordering::first_seen_calls(projection);
    for task_id in ordering::ordered_task_ids(projection) {
        append_task_cell(&mut cells, projection, task_id);
        append_task_calls(&mut cells, projection, details, &call_order, Some(task_id));
    }
    append_task_calls(&mut cells, projection, details, &call_order, None);
    append_orphan_calls(&mut cells, projection, details, &call_order);
    cells
}

fn append_plan_cell(
    cells: &mut Vec<RunPresentationCellV1>,
    projection: &RunProjection,
    quarantine: Option<&completion_quarantine::CompletionQuarantine>,
) {
    let Some(plan) = projection.plan.as_ref() else {
        return;
    };
    let status = quarantine.map_or(plan.status, |quarantine| quarantine.status(plan.status));
    let plan_cell = cell(
        RunCellKey::item(plan.item_id, RunCellRoleV1::Plan, 0),
        RunCellImportanceV1::Essential,
        RunPresentationPayloadV1::Plan(PlanPresentationV1 {
            revision: plan.revision,
            title: plan.title.clone(),
            status,
        }),
    );
    cells.push(qualify_plan_completion(plan_cell, plan.status, quarantine));
}

fn qualify_plan_completion(
    cell: RunPresentationCellV1,
    recorded: RunItemStatus,
    quarantine: Option<&completion_quarantine::CompletionQuarantine>,
) -> RunPresentationCellV1 {
    if !matches!(recorded, RunItemStatus::Completed | RunItemStatus::Skipped) {
        return cell;
    }
    match quarantine {
        Some(quarantine) => quarantine.qualify(cell, recorded),
        None => cell,
    }
}

fn append_task_cell(
    cells: &mut Vec<RunPresentationCellV1>,
    projection: &RunProjection,
    task_id: RunTaskId,
) {
    let Some(task) = projection.tasks.get(&task_id) else {
        return;
    };
    cells.push(cell(
        RunCellKey::item(task.item_id, RunCellRoleV1::Task, 0),
        RunCellImportanceV1::Essential,
        RunPresentationPayloadV1::Task(TaskPresentationV1 {
            task_id,
            title: task.title.clone(),
            status: task.status,
            detail: task.detail.clone(),
        }),
    ));
}

fn append_task_calls(
    cells: &mut Vec<RunPresentationCellV1>,
    projection: &RunProjection,
    details: &BTreeMap<RunCallId, CallDetails>,
    call_order: &[RunCallId],
    task_id: Option<RunTaskId>,
) {
    for call_id in call_order {
        let Some(call) = projection.calls.get(call_id) else {
            continue;
        };
        if call.task_id == task_id {
            cells.push(call_cell(projection, *call_id, call, details.get(call_id)));
        }
    }
}

fn append_orphan_calls(
    cells: &mut Vec<RunPresentationCellV1>,
    projection: &RunProjection,
    details: &BTreeMap<RunCallId, CallDetails>,
    call_order: &[RunCallId],
) {
    for call_id in call_order {
        let Some(call) = projection.calls.get(call_id) else {
            continue;
        };
        let orphaned = call
            .task_id
            .is_some_and(|task_id| !projection.tasks.contains_key(&task_id));
        if orphaned {
            cells.push(call_cell(projection, *call_id, call, details.get(call_id)));
        }
    }
}

fn call_cell(
    projection: &RunProjection,
    call_id: RunCallId,
    call: &super::super::CallProjection,
    details: Option<&CallDetails>,
) -> RunPresentationCellV1 {
    let details = details.cloned().unwrap_or_default();
    match call.kind {
        CallKind::Tool => tool_call_cell(projection, call_id, call, details),
        CallKind::Model => model_call_cell(call_id, call, details),
    }
}

fn tool_call_cell(
    projection: &RunProjection,
    call_id: RunCallId,
    call: &super::super::CallProjection,
    details: CallDetails,
) -> RunPresentationCellV1 {
    let related_artifacts = related_artifacts(projection, call.item_id, &details);
    cell(
        RunCellKey::item(call.item_id, RunCellRoleV1::ToolCall, 0),
        RunCellImportanceV1::Essential,
        RunPresentationPayloadV1::ToolCall(ToolCallPresentationV1 {
            call_id,
            task_id: call.task_id,
            parent_item_id: call.parent_item_id,
            label: call.label.clone(),
            status: call.status,
            runtime: details.runtime,
            model: details.model,
            safe_option_names: details.safe_option_names,
            cost: call.cost,
            preview: details.preview,
            warning_count: details.warning_count,
            error_count: details.error_count,
            result_artifact: details.result_artifact,
            related_artifacts,
            rejection: details.rejection,
            timing: details.timing,
        }),
    )
}

fn related_artifacts(
    projection: &RunProjection,
    item_id: RunItemId,
    details: &CallDetails,
) -> Vec<ArtifactReference> {
    let mut artifacts = matching_result_artifacts(item_id, details);
    for artifact in produced_artifacts(projection, item_id) {
        if !artifacts
            .iter()
            .any(|known| known.digest == artifact.digest)
        {
            artifacts.push(artifact.clone());
        }
    }
    artifacts
}

fn matching_result_artifacts(item_id: RunItemId, details: &CallDetails) -> Vec<ArtifactReference> {
    details
        .result_artifact
        .iter()
        .filter(|artifact| artifact.producing_item_id == item_id)
        .cloned()
        .collect()
}

fn produced_artifacts(
    projection: &RunProjection,
    item_id: RunItemId,
) -> impl Iterator<Item = &ArtifactReference> {
    projection.timeline.iter().filter_map(move |envelope| {
        let RunItemV1::ArtifactProduced { artifact } = &envelope.item else {
            return None;
        };
        (artifact.producing_item_id == item_id).then_some(artifact)
    })
}

fn model_call_cell(
    call_id: RunCallId,
    call: &super::super::CallProjection,
    details: CallDetails,
) -> RunPresentationCellV1 {
    cell(
        RunCellKey::item(call.item_id, RunCellRoleV1::ModelCall, 0),
        RunCellImportanceV1::Detail,
        RunPresentationPayloadV1::ModelCall(ModelCallPresentationV1 {
            call_id,
            task_id: call.task_id,
            parent_item_id: call.parent_item_id,
            provider: details.provider,
            model: details.model.unwrap_or_else(|| call.label.clone()),
            status: call.status,
            latency_ms: details.latency_ms,
            usage: details.usage,
            cost: call.cost,
            error_class: details.error_class,
            failure: details.failure,
            timing: details.timing,
        }),
    )
}
