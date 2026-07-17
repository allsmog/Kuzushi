use super::{PhaseAttemptCompletedV2, PhaseAttemptLedgerV2, TargetContentIdentity};
use crate::run_lifecycle::{RunAttemptId, RunItemV1, WorkflowContinuation};
use crate::workflow_attempts::RecoveredPhaseAttemptLedger;
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn validate_v2_attempts(
    target: &Path,
    recovered: &mut RecoveredPhaseAttemptLedger,
    v2: &PhaseAttemptLedgerV2,
    failures: &mut Vec<String>,
) {
    for (attempt_id, completed) in &v2.attempts {
        let id = attempt_id.to_string();
        let validation =
            validate_v2_receipt_reference(target, completed).and_then(|continuation| {
                let referenced = validate_referenced_run_identity(target, completed)?;
                validate_v1_projection(
                    recovered,
                    completed,
                    &continuation,
                    &referenced.target_snapshot,
                )
            });
        if let Err(error) = validation {
            recovered.ledger.block_content_reuse(id.clone());
            failures.push(format!("attempt {id}: {error}"));
            continue;
        }
        if !content_identity_matches_current(target, completed, &recovered.ledger) {
            recovered.ledger.block_content_reuse(id);
        }
    }
}

pub(super) fn block_unverifiable_legacy_v1_attempts(
    target: &Path,
    recovered: &mut RecoveredPhaseAttemptLedger,
    v2: &PhaseAttemptLedgerV2,
) {
    let blocked = recovered
        .ledger
        .attempts()
        .filter(|record| !has_v2_attempt(&record.completed.attempt_id, v2))
        .filter(|record| !legacy_attempt_reuse_is_verifiable(target, &record.completed))
        .map(|record| record.completed.attempt_id.clone())
        .collect::<Vec<_>>();
    for attempt_id in blocked {
        recovered.ledger.block_content_reuse(attempt_id);
    }
}

fn has_v2_attempt(attempt_id: &str, v2: &PhaseAttemptLedgerV2) -> bool {
    RunAttemptId::parse(attempt_id)
        .ok()
        .is_some_and(|attempt_id| v2.attempts.contains_key(&attempt_id))
}

fn legacy_attempt_reuse_is_verifiable(
    target: &Path,
    completed: &crate::workflow_attempts::PhaseAttemptCompleted,
) -> bool {
    let referenced = super::identity::referenced_run_state(target, &completed.run_refs);
    referenced
        .target_snapshot
        .equivalent_to(&completed.target_snapshot)
        && current_target_matches_identity(target, &referenced.content_identity)
}

pub(super) fn validate_v2_receipt_reference(
    target: &Path,
    completed: &PhaseAttemptCompletedV2,
) -> Result<WorkflowContinuation> {
    let read =
        crate::run_lifecycle::load_run_projection(target, completed.final_receipt.run_id.as_str())?;
    super::receipt::ensure_typed_projection(&read)?;
    let envelope = read
        .projection
        .timeline
        .iter()
        .find(|item| item.item_id == completed.final_receipt.item_id)
        .context("final receipt item is missing")?;
    anyhow::ensure!(
        envelope.event_hash == completed.final_receipt.event_hash.as_str(),
        "final receipt event hash changed"
    );
    anyhow::ensure!(
        envelope.attempt_id == Some(completed.attempt_id)
            && envelope.phase == Some(completed.phase),
        "final receipt attempt or phase identity changed"
    );
    validate_receipt_item(completed, envelope)
}

fn validate_receipt_item(
    completed: &PhaseAttemptCompletedV2,
    envelope: &crate::run_lifecycle::RunItemEnvelopeV1,
) -> Result<WorkflowContinuation> {
    let RunItemV1::PhaseReceipt {
        run_ids,
        status,
        continuation,
        ..
    } = &envelope.item
    else {
        anyhow::bail!("final receipt reference is not a PhaseReceipt item");
    };
    anyhow::ensure!(
        run_ids == &completed.run_refs,
        "phase receipt run references changed"
    );
    anyhow::ensure!(
        *status == completed.outcome,
        "phase receipt outcome changed"
    );
    Ok(continuation.clone())
}

fn validate_v1_projection(
    recovered: &RecoveredPhaseAttemptLedger,
    completed: &PhaseAttemptCompletedV2,
    continuation: &WorkflowContinuation,
    target_snapshot: &crate::workflow_attempts::PhaseTargetSnapshot,
) -> Result<()> {
    let id = completed.attempt_id.to_string();
    let record = recovered
        .ledger
        .attempt(&id)
        .context("workflow-v1 compatibility projection is missing")?;
    validate_v1_attempt_identity(record, completed, target_snapshot)?;
    validate_v1_continuation(record, continuation)
}

fn validate_v1_attempt_identity(
    record: &crate::workflow_attempts::PhaseAttemptRecord,
    completed: &PhaseAttemptCompletedV2,
    target_snapshot: &crate::workflow_attempts::PhaseTargetSnapshot,
) -> Result<()> {
    let run_refs = completed
        .run_refs
        .iter()
        .map(|run_id| run_id.as_str())
        .collect::<Vec<_>>();
    anyhow::ensure!(
        record.completed.phase == completed.phase,
        "workflow-v1 phase changed"
    );
    anyhow::ensure!(
        record.completed.target_snapshot.equivalent_to(target_snapshot),
        "workflow-v1 target snapshot disagrees with referenced runs"
    );
    anyhow::ensure!(
        record
            .completed
            .run_refs
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            == run_refs,
        "workflow-v1 run references changed"
    );
    anyhow::ensure!(
        super::receipt::outcome_status(record.completed.outcome) == completed.outcome,
        "workflow-v1 outcome changed"
    );
    Ok(())
}

fn validate_v1_continuation(
    record: &crate::workflow_attempts::PhaseAttemptRecord,
    continuation: &WorkflowContinuation,
) -> Result<()> {
    let recommendation = record
        .completed
        .receipt
        .as_ref()
        .and_then(|receipt| receipt.recommended_next.as_deref());
    anyhow::ensure!(
        recommendation == Some(continuation.operator_label().as_str()),
        "workflow-v1 continuation projection changed"
    );
    Ok(())
}

fn validate_referenced_run_identity(
    target: &Path,
    completed: &PhaseAttemptCompletedV2,
) -> Result<super::identity::ReferencedRunState> {
    let run_refs = completed
        .run_refs
        .iter()
        .map(|run_id| run_id.to_string())
        .collect::<Vec<_>>();
    let referenced = super::identity::referenced_run_state(target, &run_refs);
    anyhow::ensure!(
        content_identities_agree(
            &completed.target_content_identity,
            &referenced.content_identity
        ),
        "target content identity disagrees with referenced runs"
    );
    anyhow::ensure!(
        crate::workflow_attempts::target_identities_match(
            completed.target.as_str(),
            &referenced.target_snapshot.target,
        ),
        "target path disagrees with referenced runs"
    );
    Ok(referenced)
}

fn content_identities_agree(
    stored: &TargetContentIdentity,
    referenced: &TargetContentIdentity,
) -> bool {
    matches!(
        (stored, referenced),
        (
            TargetContentIdentity::Unavailable { .. },
            TargetContentIdentity::Unavailable { .. }
        )
    ) || stored == referenced
}

fn content_identity_matches_current(
    target: &Path,
    completed: &PhaseAttemptCompletedV2,
    ledger: &crate::workflow_attempts::PhaseAttemptLedger,
) -> bool {
    if ledger.attempt(&completed.attempt_id.to_string()).is_none() {
        return false;
    }
    current_target_matches_identity(target, &completed.target_content_identity)
}

fn current_target_matches_identity(target: &Path, identity: &TargetContentIdentity) -> bool {
    match identity {
        TargetContentIdentity::CleanGitCommit { commit } => {
            crate::workspace::target_git_metadata(target)
                .is_some_and(|git| !git.dirty && git.sha == commit.as_str())
        }
        TargetContentIdentity::IndexedSnapshot {
            tree_hash: Some(expected),
            ..
        } => crate::incremental_index::current_workspace_tree_hash(target)
            .is_ok_and(|current| current == expected.as_str()),
        TargetContentIdentity::IndexedSnapshot {
            tree_hash: None, ..
        } => false,
        TargetContentIdentity::Unavailable { .. } => false,
    }
}

pub(super) fn block_unreferenced_uuid_attempts(
    recovered: &mut RecoveredPhaseAttemptLedger,
    v2: &PhaseAttemptLedgerV2,
    failures: &mut Vec<String>,
) {
    let missing = recovered
        .ledger
        .attempts()
        .filter_map(|record| {
            let id = RunAttemptId::parse(&record.completed.attempt_id).ok()?;
            (!v2.attempts.contains_key(&id)).then(|| record.completed.attempt_id.clone())
        })
        .collect::<Vec<_>>();
    for id in missing {
        recovered.ledger.block_content_reuse(id.clone());
        failures.push(format!("attempt {id}: workflow-v2 reference is missing"));
    }
}
