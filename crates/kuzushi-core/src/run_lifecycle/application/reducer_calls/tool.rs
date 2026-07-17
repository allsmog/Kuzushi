use super::super::super::super::{CallKind, RunProjection};
use super::super::ensure_legacy;
use super::{ensure_call_identity, new_call, required_call_id};
use crate::run_lifecycle::{
    ArtifactReference, RunCallId, RunItemEnvelopeV1, RunItemStatus, SafeText,
};
use crate::runtime::RuntimeCostReport;
use anyhow::Result;

pub(in crate::run_lifecycle::application) fn reject_tool_call(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
) -> Result<()> {
    let call_id = required_call_id(envelope)?;
    let Some(call) = projection.calls.get_mut(&call_id) else {
        ensure_legacy(envelope, "call rejection without request")?;
        insert_legacy_tool_finish(
            projection,
            envelope,
            call_id,
            RunItemStatus::Failed,
            RuntimeCostReport::UNAVAILABLE,
            None,
            Vec::new(),
            0,
            1,
        );
        return Ok(());
    };
    anyhow::ensure!(
        call.status == RunItemStatus::Pending,
        "call rejected after start"
    );
    ensure_call_identity(call, envelope)?;
    call.status = RunItemStatus::Failed;
    call.completed_at_ms = Some(envelope.occurred_at_ms);
    call.error_count = 1;
    Ok(())
}

pub(in crate::run_lifecycle::application) fn finish_tool_call(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
    status: RunItemStatus,
    cost: RuntimeCostReport,
    result_artifact: &Option<ArtifactReference>,
    preview: Vec<SafeText>,
    warning_count: u64,
    error_count: u64,
) -> Result<()> {
    anyhow::ensure!(status.is_terminal(), "call finish is not terminal");
    let call_id = required_call_id(envelope)?;
    validate_result_settlement(projection, envelope, call_id, result_artifact.as_ref())?;
    if update_existing_tool_call(
        projection,
        envelope,
        call_id,
        status,
        cost,
        result_artifact.clone(),
        preview.clone(),
        warning_count,
        error_count,
    )? {
        return Ok(());
    }
    ensure_legacy(envelope, "call finish without start")?;
    insert_legacy_tool_finish(
        projection,
        envelope,
        call_id,
        status,
        cost,
        result_artifact.clone(),
        preview,
        warning_count,
        error_count,
    );
    Ok(())
}

fn validate_result_artifact(
    envelope: &RunItemEnvelopeV1,
    artifact: Option<&ArtifactReference>,
) -> Result<()> {
    let Some(artifact) = artifact else {
        return Ok(());
    };
    anyhow::ensure!(
        artifact.producing_item_id == envelope.item_id,
        "result artifact producer does not match finished call"
    );
    Ok(())
}

fn validate_result_settlement(
    projection: &RunProjection,
    envelope: &RunItemEnvelopeV1,
    call_id: RunCallId,
    artifact: Option<&ArtifactReference>,
) -> Result<()> {
    validate_result_artifact(envelope, artifact)?;
    validate_canonical_result_owner(projection, call_id, artifact)
}

fn validate_canonical_result_owner(
    projection: &RunProjection,
    call_id: RunCallId,
    artifact: Option<&ArtifactReference>,
) -> Result<()> {
    let Some(artifact) = artifact else {
        return Ok(());
    };
    let conflict = projection.calls.iter().any(|(existing_id, call)| {
        *existing_id != call_id
            && call
                .result_artifact
                .as_ref()
                .is_some_and(|existing| same_canonical_result(existing, artifact))
    });
    anyhow::ensure!(
        !conflict,
        "canonical result path or digest already belongs to another call"
    );
    Ok(())
}

fn same_canonical_result(left: &ArtifactReference, right: &ArtifactReference) -> bool {
    left.path == right.path || left.digest == right.digest
}

#[allow(clippy::too_many_arguments)]
fn insert_legacy_tool_finish(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
    call_id: RunCallId,
    status: RunItemStatus,
    cost: RuntimeCostReport,
    result_artifact: Option<ArtifactReference>,
    preview: Vec<SafeText>,
    warning_count: u64,
    error_count: u64,
) {
    let mut call = new_call(
        envelope,
        CallKind::Tool,
        &SafeText::operator_visible("legacy call"),
        status,
    );
    call.completed_at_ms = Some(envelope.occurred_at_ms);
    call.cost = cost;
    call.result_artifact = result_artifact;
    call.preview = preview;
    call.warning_count = warning_count;
    call.error_count = error_count;
    projection.calls.insert(call_id, call);
    projection.call_order.push(call_id);
}

#[allow(clippy::too_many_arguments)]
fn update_existing_tool_call(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
    call_id: RunCallId,
    status: RunItemStatus,
    cost: RuntimeCostReport,
    result_artifact: Option<ArtifactReference>,
    preview: Vec<SafeText>,
    warning_count: u64,
    error_count: u64,
) -> Result<bool> {
    let Some(call) = projection.calls.get_mut(&call_id) else {
        return Ok(false);
    };
    let pre_start_terminal = matches!(status, RunItemStatus::Skipped | RunItemStatus::Failed);
    let valid = call.status == RunItemStatus::Running
        || (pre_start_terminal && call.status == RunItemStatus::Pending);
    anyhow::ensure!(valid, "call finished from invalid state");
    ensure_call_identity(call, envelope)?;
    call.status = status;
    call.completed_at_ms = Some(envelope.occurred_at_ms);
    call.cost = cost;
    call.result_artifact = result_artifact;
    call.preview = preview;
    call.warning_count = warning_count;
    call.error_count = error_count;
    Ok(true)
}
