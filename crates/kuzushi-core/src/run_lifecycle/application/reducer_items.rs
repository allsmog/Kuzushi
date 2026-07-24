use super::super::{CallKind, RunProjection};
use crate::run_lifecycle::{RunItemEnvelopeV1, RunItemV1};
use anyhow::Result;

#[path = "reducer_calls.rs"]
mod reducer_calls;
#[path = "reducer_domain.rs"]
mod reducer_domain;
#[path = "reducer_terminal.rs"]
mod reducer_terminal;
#[path = "reducer_work.rs"]
mod reducer_work;

use reducer_calls::{
    apply_model_finished, finish_tool_call, insert_call, reject_tool_call, require_running_call,
    start_call, start_model_call,
};
use reducer_domain::apply_domain_item;
use reducer_work::{apply_plan, apply_task};

pub(super) fn apply_item(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
) -> Result<()> {
    match &envelope.item {
        RunItemV1::PlanUpdated {
            revision,
            title,
            status,
            task_ids,
        } => apply_plan(projection, envelope, *revision, title, *status, task_ids),
        RunItemV1::TaskUpdated {
            title,
            status,
            detail,
        } => apply_task(projection, envelope, title, *status, detail),
        item if is_tool_call_item(item) => apply_tool_call_item(projection, envelope),
        item if is_model_call_item(item) => apply_model_call_item(projection, envelope),
        _ => apply_domain_item(projection, envelope),
    }
}

fn is_tool_call_item(item: &RunItemV1) -> bool {
    matches!(
        item,
        RunItemV1::ToolCallRequested { .. }
            | RunItemV1::ToolCallStarted { .. }
            | RunItemV1::ToolCallRejected { .. }
            | RunItemV1::ToolCallProgress { .. }
            | RunItemV1::ToolCallFinished { .. }
    )
}

fn is_model_call_item(item: &RunItemV1) -> bool {
    matches!(
        item,
        RunItemV1::ModelCallStarted { .. } | RunItemV1::ModelCallFinished { .. }
    )
}

fn apply_tool_call_item(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
) -> Result<()> {
    match &envelope.item {
        RunItemV1::ToolCallRequested { tool_name, .. } => {
            insert_call(projection, envelope, CallKind::Tool, tool_name)
        }
        RunItemV1::ToolCallStarted {
            tool_name,
            runtime,
            model,
        } => start_call(
            projection,
            envelope,
            CallKind::Tool,
            tool_name,
            runtime,
            model,
        ),
        RunItemV1::ToolCallRejected { .. } => apply_rejected_call(projection, envelope),
        RunItemV1::ToolCallProgress { .. } => require_running_call(projection, envelope),
        RunItemV1::ToolCallFinished { .. } => apply_finished_tool_call(projection, envelope),
        _ => unreachable!("tool call item was classified before dispatch"),
    }
}

fn apply_rejected_call(projection: &mut RunProjection, envelope: &RunItemEnvelopeV1) -> Result<()> {
    reject_tool_call(projection, envelope)
}

fn apply_finished_tool_call(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
) -> Result<()> {
    let RunItemV1::ToolCallFinished {
        status,
        cost,
        result_artifact,
        preview,
        warning_count,
        error_count,
    } = &envelope.item
    else {
        unreachable!("caller classified a finished tool call")
    };
    finish_tool_call(
        projection,
        envelope,
        *status,
        *cost,
        result_artifact,
        preview.clone(),
        *warning_count,
        *error_count,
    )
}

fn apply_model_call_item(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
) -> Result<()> {
    match &envelope.item {
        RunItemV1::ModelCallStarted {
            provider, model, ..
        } => start_model_call(projection, envelope, provider, model),
        RunItemV1::ModelCallFinished { .. } => apply_finished_model_call(projection, envelope),
        _ => unreachable!("model call item was classified before dispatch"),
    }
}

fn apply_finished_model_call(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
) -> Result<()> {
    let RunItemV1::ModelCallFinished {
        provider,
        model,
        status,
        latency_ms,
        usage,
        cost,
        error_class,
    } = &envelope.item
    else {
        unreachable!("caller classified a finished model call")
    };
    apply_model_finished(
        projection,
        envelope,
        provider,
        model,
        *status,
        *latency_ms,
        usage,
        *cost,
        error_class,
    )
}
