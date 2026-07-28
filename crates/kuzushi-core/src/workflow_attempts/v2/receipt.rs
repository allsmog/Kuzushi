use super::{
    PhaseAttemptCompletedV2, PhaseReceiptBuilder, PhaseReceiptReferenceV2, TargetContentIdentity,
};
use crate::run_lifecycle::{
    ProjectionHealth, RunAttemptId, RunId, RunItemEnvelopeV1, RunItemId, RunItemRecord,
    RunItemSource, RunItemStatus, RunItemV1, RunObservationHandle, RunProjectionSource, SafeText,
};
use crate::workflow_attempts::{PhaseAttemptCompleted, PhaseAttemptOutcome};
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn emit_or_load_phase_receipt(
    target: &Path,
    completed: &PhaseAttemptCompleted,
    attempt_id: RunAttemptId,
) -> Result<RunItemEnvelopeV1> {
    let final_run = completed
        .run_refs
        .last()
        .context("phase attempt has no run reference")?;
    let read = crate::run_lifecycle::load_run_projection(target, final_run)?;
    ensure_typed_projection(&read)?;
    if let Some(item) = read.projection.timeline.iter().find(|item| {
        item.attempt_id == Some(attempt_id) && matches!(item.item, RunItemV1::PhaseReceipt { .. })
    }) {
        return Ok(item.clone());
    }
    let observation = RunObservationHandle::jsonl(target.to_path_buf(), final_run.clone())?
        .for_attempt(attempt_id, completed.phase);
    observation.emit_and_flush(RunItemRecord::new(
        RunItemId::new(),
        RunItemSource::Workflow,
        phase_receipt_item(target, completed)?,
    ))
}

pub(super) fn ensure_typed_projection(
    read: &crate::run_lifecycle::RunProjectionRead,
) -> Result<()> {
    anyhow::ensure!(
        read.source == RunProjectionSource::TypedV1,
        "final phase run has no typed stream"
    );
    match &read.projection.health {
        ProjectionHealth::Healthy => Ok(()),
        ProjectionHealth::Degraded { reason, .. } => {
            anyhow::bail!("final phase run stream is degraded: {reason}")
        }
    }
}

fn phase_receipt_item(target: &Path, completed: &PhaseAttemptCompleted) -> Result<RunItemV1> {
    let projections = load_attempt_projections(target, &completed.run_refs)?;
    let run_ids = completed
        .run_refs
        .iter()
        .map(|run_id| RunId::parse(run_id))
        .collect::<Result<Vec<_>>>()?;
    PhaseReceiptBuilder::new(
        completed.phase,
        outcome_status(completed.outcome),
        &run_ids,
        &projections,
    )
    .with_selection_blocked_reason(completed.selection_blocked_reason.as_deref())
    .build()
}

fn load_attempt_projections(
    target: &Path,
    run_refs: &[String],
) -> Result<Vec<crate::run_lifecycle::RunProjection>> {
    run_refs
        .iter()
        .map(|run_id| {
            let read = crate::run_lifecycle::load_run_projection(target, run_id)?;
            ensure_typed_projection(&read)?;
            Ok(read.projection)
        })
        .collect()
}

pub(super) fn outcome_status(outcome: PhaseAttemptOutcome) -> RunItemStatus {
    match outcome {
        PhaseAttemptOutcome::Completed => RunItemStatus::Completed,
        PhaseAttemptOutcome::Partial => RunItemStatus::Partial,
        PhaseAttemptOutcome::Blocked => RunItemStatus::Blocked,
        PhaseAttemptOutcome::Failed => RunItemStatus::Failed,
        PhaseAttemptOutcome::Canceled => RunItemStatus::Canceled,
    }
}

pub(super) fn completed_v2(
    completed: &PhaseAttemptCompleted,
    receipt: RunItemEnvelopeV1,
    target_content_identity: TargetContentIdentity,
) -> Result<PhaseAttemptCompletedV2> {
    Ok(PhaseAttemptCompletedV2 {
        attempt_id: RunAttemptId::parse(&completed.attempt_id)?,
        phase: completed.phase,
        run_refs: completed
            .run_refs
            .iter()
            .map(|run_id| RunId::parse(run_id))
            .collect::<Result<Vec<_>>>()?,
        final_receipt: PhaseReceiptReferenceV2 {
            run_id: receipt.run_id,
            item_id: receipt.item_id,
            event_hash: SafeText::operator_visible(receipt.event_hash),
        },
        outcome: outcome_status(completed.outcome),
        target: SafeText::operator_visible(&completed.target_snapshot.target),
        target_content_identity,
    })
}
