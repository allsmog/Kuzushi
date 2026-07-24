use super::super::super::{CallKind, CallProjection, RunProjection};
use crate::run_lifecycle::{ModelUsage, RunCallId, RunItemEnvelopeV1, RunItemStatus, SafeText};
use crate::runtime::RuntimeCostReport;
use anyhow::Result;

#[path = "reducer_calls/model.rs"]
mod model;
#[path = "reducer_calls/tool.rs"]
mod tool;
pub(super) use model::{apply_model_finished, start_model_call};
pub(super) use tool::{finish_tool_call, reject_tool_call};

pub(super) fn insert_call(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
    kind: CallKind,
    label: &SafeText,
) -> Result<()> {
    let call_id = required_call_id(envelope)?;
    anyhow::ensure!(
        !projection.calls.contains_key(&call_id),
        "call requested twice"
    );
    projection.calls.insert(
        call_id,
        new_call(envelope, kind, label, RunItemStatus::Pending),
    );
    projection.call_order.push(call_id);
    Ok(())
}

pub(super) fn start_call(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
    kind: CallKind,
    label: &SafeText,
    runtime: &Option<SafeText>,
    model: &Option<SafeText>,
) -> Result<()> {
    let call_id = required_call_id(envelope)?;
    if let Some(call) = projection.calls.get_mut(&call_id) {
        anyhow::ensure!(
            call.kind == kind && call.status == RunItemStatus::Pending,
            "call cannot start"
        );
        ensure_call_identity(call, envelope)?;
        anyhow::ensure!(&call.label == label, "call label changed at start");
        call.status = RunItemStatus::Running;
        call.runtime = runtime.clone();
        call.model = model.clone();
        call.started_at_ms = Some(envelope.occurred_at_ms);
        return Ok(());
    }
    anyhow::bail!("call start without request")
}

pub(super) fn require_running_call(
    projection: &RunProjection,
    envelope: &RunItemEnvelopeV1,
) -> Result<()> {
    let call_id = required_call_id(envelope)?;
    let call = projection
        .calls
        .get(&call_id)
        .ok_or_else(|| anyhow::anyhow!("orphan call progress"))?;
    anyhow::ensure!(
        call.status == RunItemStatus::Running,
        "progress for non-running call"
    );
    Ok(())
}

fn new_call(
    envelope: &RunItemEnvelopeV1,
    kind: CallKind,
    label: &SafeText,
    status: RunItemStatus,
) -> CallProjection {
    CallProjection {
        item_id: envelope.item_id,
        task_id: envelope.task_id,
        parent_item_id: envelope.parent_item_id,
        kind,
        label: label.clone(),
        status,
        runtime: None,
        model: None,
        provider: None,
        requested_at_ms: (kind == CallKind::Tool).then_some(envelope.occurred_at_ms),
        started_at_ms: (status == RunItemStatus::Running).then_some(envelope.occurred_at_ms),
        completed_at_ms: status.is_terminal().then_some(envelope.occurred_at_ms),
        latency_ms: None,
        usage: ModelUsage {
            input_tokens: None,
            output_tokens: None,
        },
        error_class: None,
        cost: RuntimeCostReport::UNAVAILABLE,
        preview: Vec::new(),
        warning_count: 0,
        error_count: 0,
        result_artifact: None,
        related_artifact_ids: Vec::new(),
        first_seen_seq: envelope.seq,
    }
}

fn ensure_call_identity(call: &CallProjection, envelope: &RunItemEnvelopeV1) -> Result<()> {
    anyhow::ensure!(call.item_id == envelope.item_id, "call item ID changed");
    anyhow::ensure!(
        call.task_id == envelope.task_id,
        "call task identity changed"
    );
    anyhow::ensure!(
        call.parent_item_id == envelope.parent_item_id,
        "call parent identity changed"
    );
    Ok(())
}

fn required_call_id(envelope: &RunItemEnvelopeV1) -> Result<RunCallId> {
    envelope
        .call_id
        .ok_or_else(|| anyhow::anyhow!("call item lacks call ID"))
}
