use super::{
    PhaseAttemptCompleted, PhaseAttemptDisposition, PhaseAttemptDispositionRecorded,
    PhaseAttemptEvent, PhaseAttemptOutcome, PhaseAttemptRecord, PhaseCheckpointSkipped,
    PhaseTargetSnapshot, ProofDeferralRecorded,
};
use crate::WorkflowPhase;
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};

mod validation;
use validation::{
    validate_completed, validate_disposition, validate_proof_deferral, validate_target_snapshot,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhaseAttemptLedger {
    attempts: BTreeMap<String, PhaseAttemptRecord>,
    attempt_order: BTreeMap<String, usize>,
    disposition_order: BTreeMap<String, usize>,
    skipped_checkpoints: Vec<PhaseCheckpointSkipped>,
    proof_deferrals: Vec<ProofDeferralRecorded>,
    content_reuse_blocked_attempts: BTreeSet<String>,
    content_drift_blocked_attempts: BTreeSet<String>,
}

impl PhaseAttemptLedger {
    pub fn from_events(events: impl IntoIterator<Item = PhaseAttemptEvent>) -> Result<Self> {
        let mut ledger = Self::default();
        for (sequence, event) in events.into_iter().enumerate() {
            ledger.apply(event, sequence)?;
        }
        Ok(ledger)
    }

    /// Remove non-phase results only from this in-memory projection. Raw
    /// events and canonical run history remain available for inspection.
    pub(super) fn exclude_from_phase_projection(&mut self, excluded: &BTreeSet<String>) {
        self.attempts.retain(|id, _| !excluded.contains(id));
        self.attempt_order.retain(|id, _| !excluded.contains(id));
        self.disposition_order
            .retain(|id, _| !excluded.contains(id));
        self.content_reuse_blocked_attempts
            .retain(|id| !excluded.contains(id));
        self.content_drift_blocked_attempts
            .retain(|id| !excluded.contains(id));
    }

    pub fn attempts(&self) -> impl DoubleEndedIterator<Item = &PhaseAttemptRecord> {
        self.attempts.values()
    }

    pub fn attempt(&self, attempt_id: &str) -> Option<&PhaseAttemptRecord> {
        self.attempts.get(attempt_id)
    }

    /// Whether `later_attempt_id` completed after `earlier_attempt_id` in the
    /// durable ledger. Append order breaks same-second timestamp ties.
    pub fn attempt_completed_after(
        &self,
        earlier_attempt_id: &str,
        later_attempt_id: &str,
    ) -> bool {
        let Some(earlier) = self.attempts.get(earlier_attempt_id) else {
            return false;
        };
        let Some(later) = self.attempts.get(later_attempt_id) else {
            return false;
        };
        self.attempt_sort_key(later) > self.attempt_sort_key(earlier)
    }

    /// Whether this target has ever entered the durable attempt protocol for
    /// `phase`. Snapshot revisions are intentionally ignored: once a phase has
    /// modern attempt history, its artifacts must never be reclassified as
    /// pre-attempt legacy evidence after a revision change or disposition.
    pub fn has_attempt_for_target(
        &self,
        phase: WorkflowPhase,
        snapshot: &PhaseTargetSnapshot,
    ) -> bool {
        self.attempts.values().any(|record| {
            record.completed.phase == phase
                && super::target_identities_match(
                    &record.completed.target_snapshot.target,
                    &snapshot.target,
                )
        })
    }

    pub fn latest_for(&self, snapshot: &PhaseTargetSnapshot) -> Option<&PhaseAttemptRecord> {
        self.attempts
            .values()
            .filter(|record| record.completed.target_snapshot.equivalent_to(snapshot))
            .max_by_key(|record| self.attempt_sort_key(record))
    }

    pub fn unresolved_for(
        &self,
        phase: WorkflowPhase,
        snapshot: &PhaseTargetSnapshot,
    ) -> Option<&PhaseAttemptRecord> {
        self.attempts
            .values()
            .filter(|record| phase_record_matches(record, phase, snapshot))
            .max_by_key(|record| self.attempt_sort_key(record))
            .filter(|record| record.disposition.is_none())
    }

    pub fn selected_for(
        &self,
        phase: WorkflowPhase,
        snapshot: &PhaseTargetSnapshot,
    ) -> Option<&PhaseAttemptRecord> {
        self.attempts
            .values()
            .filter(|record| {
                selected_record_matches(record, phase, snapshot)
                    && !self
                        .content_reuse_blocked_attempts
                        .contains(&record.completed.attempt_id)
            })
            .max_by_key(|record| self.selection_sort_key(record))
    }

    /// The most recent reusable selected checkpoint for the same target,
    /// regardless of revision or dirty state.
    ///
    /// This is presentation history only: callers must never use it to
    /// advance current-revision workflow truth. Attempts whose content reuse
    /// was blocked during recovery are excluded for the same reason they are
    /// excluded from [`Self::selected_for`].
    pub fn latest_selected_for_target(
        &self,
        phase: WorkflowPhase,
        snapshot: &PhaseTargetSnapshot,
    ) -> Option<&PhaseAttemptRecord> {
        self.attempts
            .values()
            .filter(|record| {
                selected_record_matches_target(record, phase, snapshot)
                    && !self
                        .content_reuse_blocked_attempts
                        .contains(&record.completed.attempt_id)
            })
            .max_by_key(|record| self.selection_sort_key(record))
    }

    /// The newest trusted selection for this target, including an attempt
    /// whose authenticated content identity differs from the current tree.
    ///
    /// Presentation may use this to explain a checkpoint rewind. Workflow
    /// advancement must continue to use [`Self::selected_for`]. Attempts
    /// blocked for malformed or unauthenticated history remain excluded.
    pub fn latest_selected_history_for_target(
        &self,
        phase: WorkflowPhase,
        snapshot: &PhaseTargetSnapshot,
    ) -> Option<&PhaseAttemptRecord> {
        self.attempts
            .values()
            .filter(|record| {
                selected_record_matches_target(record, phase, snapshot)
                    && (!self
                        .content_reuse_blocked_attempts
                        .contains(&record.completed.attempt_id)
                        || self
                            .content_drift_blocked_attempts
                            .contains(&record.completed.attempt_id))
            })
            .max_by_key(|record| self.selection_sort_key(record))
    }

    pub fn content_reuse_is_blocked(&self, attempt_id: &str) -> bool {
        self.content_reuse_blocked_attempts.contains(attempt_id)
    }

    pub(crate) fn block_content_reuse(&mut self, attempt_id: impl Into<String>) {
        self.content_reuse_blocked_attempts
            .insert(attempt_id.into());
    }

    pub(crate) fn block_content_reuse_for_drift(&mut self, attempt_id: impl Into<String>) {
        let attempt_id = attempt_id.into();
        self.content_reuse_blocked_attempts
            .insert(attempt_id.clone());
        self.content_drift_blocked_attempts.insert(attempt_id);
    }

    pub fn phase_was_skipped(&self, phase: WorkflowPhase, snapshot: &PhaseTargetSnapshot) -> bool {
        self.skipped_checkpoints.iter().any(|checkpoint| {
            checkpoint.phase == phase && checkpoint.target_snapshot.equivalent_to(snapshot)
        })
    }

    pub fn skipped_phases_for(&self, snapshot: &PhaseTargetSnapshot) -> BTreeSet<WorkflowPhase> {
        self.skipped_checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.target_snapshot.equivalent_to(snapshot))
            .map(|checkpoint| checkpoint.phase)
            .collect()
    }

    /// Whether a human explicitly deferred proof for this exact discovery
    /// generation. Durable identity can bridge a fingerprint re-key, but a
    /// different scan id or target snapshot can never reuse the decision.
    pub fn proof_is_deferred_for(
        &self,
        snapshot: &PhaseTargetSnapshot,
        fingerprint: &str,
        identity_id: Option<&str>,
        scan_id: &str,
    ) -> bool {
        self.proof_deferral_for(snapshot, fingerprint, identity_id, scan_id)
            .is_some()
    }

    /// The newest durable deferral for an exact discovery generation.
    pub fn proof_deferral_for(
        &self,
        snapshot: &PhaseTargetSnapshot,
        fingerprint: &str,
        identity_id: Option<&str>,
        scan_id: &str,
    ) -> Option<&ProofDeferralRecorded> {
        self.proof_deferrals.iter().rev().find(|record| {
            record.target_snapshot.equivalent_to(snapshot)
                && record.finding_scan_id == scan_id
                && deferral_identity_matches(record, fingerprint, identity_id)
        })
    }

    /// The newest durable deferral for an exact discovery generation,
    /// projected for display. Presentation surfaces read this instead of the
    /// raw event so the Prove page, plain output, and `kuzushi finding` all
    /// disclose the same decision.
    pub fn proof_deferral_view_for(
        &self,
        snapshot: &PhaseTargetSnapshot,
        fingerprint: &str,
        identity_id: Option<&str>,
        scan_id: &str,
    ) -> Option<super::ProofDeferralView> {
        self.proof_deferral_for(snapshot, fingerprint, identity_id, scan_id)
            .map(super::ProofDeferralView::from_record)
    }

    /// The newest durable proof deferral for the current target snapshot.
    pub fn latest_proof_deferral_for(
        &self,
        snapshot: &PhaseTargetSnapshot,
    ) -> Option<&ProofDeferralRecorded> {
        self.proof_deferrals
            .iter()
            .rev()
            .find(|record| record.target_snapshot.equivalent_to(snapshot))
    }

    fn apply(&mut self, event: PhaseAttemptEvent, sequence: usize) -> Result<()> {
        match event {
            PhaseAttemptEvent::PhaseAttemptCompleted(completed) => {
                self.apply_completed(completed, sequence)
            }
            PhaseAttemptEvent::PhaseAttemptDispositionRecorded(disposition) => {
                self.apply_disposition(disposition, sequence)
            }
            PhaseAttemptEvent::PhaseCheckpointSkipped(checkpoint) => {
                validate_target_snapshot("phase checkpoint", &checkpoint.target_snapshot)?;
                self.skipped_checkpoints.push(checkpoint);
                Ok(())
            }
            PhaseAttemptEvent::ProofDeferralRecorded(deferral) => {
                validate_proof_deferral(&deferral)?;
                self.proof_deferrals.push(deferral);
                Ok(())
            }
        }
    }

    fn apply_completed(&mut self, completed: PhaseAttemptCompleted, sequence: usize) -> Result<()> {
        validate_completed(&completed)?;
        anyhow::ensure!(
            !self.attempts.contains_key(&completed.attempt_id),
            "duplicate phase attempt id {:?}",
            completed.attempt_id
        );
        let attempt_id = completed.attempt_id.clone();
        self.attempts.insert(
            attempt_id.clone(),
            PhaseAttemptRecord {
                completed,
                disposition: None,
            },
        );
        self.attempt_order.insert(attempt_id, sequence);
        Ok(())
    }

    fn apply_disposition(
        &mut self,
        disposition: PhaseAttemptDispositionRecorded,
        sequence: usize,
    ) -> Result<()> {
        let attempt_id = disposition.attempt_id.clone();
        let record = self.attempts.get_mut(&attempt_id).with_context(|| {
            format!(
                "phase attempt disposition references unknown attempt {:?}",
                disposition.attempt_id
            )
        })?;
        validate_disposition(&record.completed, &disposition.disposition)?;
        anyhow::ensure!(
            record.disposition.is_none(),
            "phase attempt {:?} already has a disposition",
            disposition.attempt_id
        );
        record.disposition = Some(disposition);
        self.disposition_order.insert(attempt_id, sequence);
        Ok(())
    }

    fn attempt_sort_key(&self, record: &PhaseAttemptRecord) -> (u64, usize) {
        let sequence = self
            .attempt_order
            .get(&record.completed.attempt_id)
            .copied()
            .unwrap_or_default();
        (record.completed.completed_at_unix, sequence)
    }

    fn selection_sort_key(&self, record: &PhaseAttemptRecord) -> (u64, usize) {
        let recorded_at = record
            .disposition
            .as_ref()
            .map_or(0, |value| value.recorded_at_unix);
        let sequence = self
            .disposition_order
            .get(&record.completed.attempt_id)
            .copied()
            .unwrap_or_default();
        (recorded_at, sequence)
    }
}

fn deferral_identity_matches(
    record: &ProofDeferralRecorded,
    fingerprint: &str,
    identity_id: Option<&str>,
) -> bool {
    record.finding_fingerprint == fingerprint
        || record
            .identity_id
            .as_deref()
            .zip(identity_id)
            .is_some_and(|(recorded, current)| recorded == current)
}

fn phase_record_matches(
    record: &PhaseAttemptRecord,
    phase: WorkflowPhase,
    snapshot: &PhaseTargetSnapshot,
) -> bool {
    record.completed.phase == phase && record.completed.target_snapshot.equivalent_to(snapshot)
}

fn selected_record_matches(
    record: &PhaseAttemptRecord,
    phase: WorkflowPhase,
    snapshot: &PhaseTargetSnapshot,
) -> bool {
    record.completed.phase == phase
        && record.completed.target_snapshot.equivalent_to(snapshot)
        && matches!(
            record.disposition.as_ref().map(|value| &value.disposition),
            Some(PhaseAttemptDisposition::Selected { .. })
        )
}

fn selected_record_matches_target(
    record: &PhaseAttemptRecord,
    phase: WorkflowPhase,
    snapshot: &PhaseTargetSnapshot,
) -> bool {
    record.completed.phase == phase
        && super::target_identities_match(
            &record.completed.target_snapshot.target,
            &snapshot.target,
        )
        && matches!(
            record.disposition.as_ref().map(|value| &value.disposition),
            Some(PhaseAttemptDisposition::Selected { .. })
        )
}
