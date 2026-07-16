use super::{ProjectionDelta, ProjectionHealth, RunProjection};
use crate::run_lifecycle::{RunItemEnvelopeV1, RunItemPersistencePolicy, RunItemV1};
use anyhow::Result;

#[path = "reducer_items.rs"]
mod reducer_items;
use reducer_items::apply_item;

pub fn reduce_run_items(items: impl IntoIterator<Item = RunItemEnvelopeV1>) -> RunProjection {
    let mut projection = RunProjection::default();
    for envelope in items {
        if projection.health != ProjectionHealth::Healthy {
            break;
        }
        if let Err(error) = apply_envelope(&mut projection, envelope) {
            projection.degrade(error.to_string());
        }
    }
    projection
}

pub(crate) fn apply_envelope(
    projection: &mut RunProjection,
    envelope: RunItemEnvelopeV1,
) -> Result<ProjectionDelta> {
    envelope.verify_hash()?;
    RunItemPersistencePolicy::validate(&envelope.item)?;
    validate_identity(projection, &envelope)?;
    if validate_sequence(projection, &envelope)? == SequenceDisposition::Duplicate {
        return Ok(ProjectionDelta::default());
    }
    apply_item(projection, &envelope)?;
    let mut delta = projection_delta(projection, &envelope);
    projection.last_committed_seq = envelope.seq;
    projection.last_event_hash = Some(envelope.event_hash.clone());
    projection
        .committed_event_hashes
        .insert(envelope.seq, envelope.event_hash.clone());
    projection.timeline.push(envelope);
    delta.timeline_appended = true;
    Ok(delta)
}

fn projection_delta(projection: &RunProjection, envelope: &RunItemEnvelopeV1) -> ProjectionDelta {
    let mut delta = ProjectionDelta::default();
    add_scoped_identities(&mut delta, envelope);
    apply_item_delta(&mut delta, projection, envelope);
    normalize_delta(&mut delta);
    delta
}

fn add_scoped_identities(delta: &mut ProjectionDelta, envelope: &RunItemEnvelopeV1) {
    delta.task_ids.extend(envelope.task_id);
    delta.call_ids.extend(envelope.call_id);
}

fn apply_item_delta(
    delta: &mut ProjectionDelta,
    projection: &RunProjection,
    envelope: &RunItemEnvelopeV1,
) {
    match &envelope.item {
        RunItemV1::PlanUpdated { .. } => delta.plan_changed = true,
        RunItemV1::ArtifactProduced { artifact } => {
            if let Some((call_id, _)) = projection
                .calls
                .iter()
                .find(|(_, call)| call.item_id == artifact.producing_item_id)
            {
                delta.call_ids.push(*call_id);
            }
        }
        RunItemV1::OperatorQuestion { question_id, .. }
        | RunItemV1::OperatorDecision { question_id, .. } => {
            delta.question_ids.push(*question_id);
        }
        RunItemV1::TerminalOutcome { .. } => delta.terminal_changed = true,
        RunItemV1::PhaseReceipt { .. } => delta.phase_receipt_changed = true,
        _ => {}
    }
}

fn normalize_delta(delta: &mut ProjectionDelta) {
    delta.task_ids.sort_unstable();
    delta.task_ids.dedup();
    delta.call_ids.sort_unstable();
    delta.call_ids.dedup();
}

fn validate_identity(projection: &mut RunProjection, envelope: &RunItemEnvelopeV1) -> Result<()> {
    if let Some(run_id) = projection.run_id.as_ref() {
        anyhow::ensure!(run_id == &envelope.run_id, "stream mixes multiple run IDs");
    } else {
        projection.run_id = Some(envelope.run_id.clone());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SequenceDisposition {
    Apply,
    Duplicate,
}

fn validate_sequence(
    projection: &RunProjection,
    envelope: &RunItemEnvelopeV1,
) -> Result<SequenceDisposition> {
    if envelope.seq <= projection.last_committed_seq {
        let committed = projection.committed_event_hashes.get(&envelope.seq);
        anyhow::ensure!(
            committed == Some(&envelope.event_hash),
            "divergent duplicate event"
        );
        return Ok(SequenceDisposition::Duplicate);
    }
    let expected = projection.last_committed_seq + 1;
    anyhow::ensure!(
        envelope.seq == expected,
        "sequence gap: expected {expected}, got {}",
        envelope.seq
    );
    anyhow::ensure!(
        envelope.prev_event_hash == projection.last_event_hash,
        "previous-event hash mismatch at sequence {}",
        envelope.seq
    );
    Ok(SequenceDisposition::Apply)
}
