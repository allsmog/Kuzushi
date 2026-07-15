use super::{
    PhaseAttemptCompleted, PhaseAttemptDisposition, PhaseAttemptDispositionRecorded,
    PhaseAttemptEvent, PhaseAttemptOutcome, PhaseAttemptRecord, PhaseCheckpointSkipped,
    PhaseTargetSnapshot, ProofDeferralRecorded,
};
use crate::WorkflowPhase;
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhaseAttemptLedger {
    attempts: BTreeMap<String, PhaseAttemptRecord>,
    attempt_order: BTreeMap<String, usize>,
    disposition_order: BTreeMap<String, usize>,
    skipped_checkpoints: Vec<PhaseCheckpointSkipped>,
    proof_deferrals: Vec<ProofDeferralRecorded>,
}

impl PhaseAttemptLedger {
    pub fn from_events(events: impl IntoIterator<Item = PhaseAttemptEvent>) -> Result<Self> {
        let mut ledger = Self::default();
        for (sequence, event) in events.into_iter().enumerate() {
            ledger.apply(event, sequence)?;
        }
        Ok(ledger)
    }

    pub fn attempts(&self) -> impl DoubleEndedIterator<Item = &PhaseAttemptRecord> {
        self.attempts.values()
    }

    pub fn attempt(&self, attempt_id: &str) -> Option<&PhaseAttemptRecord> {
        self.attempts.get(attempt_id)
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
                && record.completed.target_snapshot.target == snapshot.target
        })
    }

    pub fn latest_for(&self, snapshot: &PhaseTargetSnapshot) -> Option<&PhaseAttemptRecord> {
        self.attempts
            .values()
            .filter(|record| &record.completed.target_snapshot == snapshot)
            .max_by_key(|record| self.attempt_sort_key(record))
    }

    pub fn unresolved_for(
        &self,
        phase: WorkflowPhase,
        snapshot: &PhaseTargetSnapshot,
    ) -> Option<&PhaseAttemptRecord> {
        self.attempts
            .values()
            .filter(|record| unresolved_record_matches(record, phase, snapshot))
            .max_by_key(|record| self.attempt_sort_key(record))
    }

    pub fn selected_for(
        &self,
        phase: WorkflowPhase,
        snapshot: &PhaseTargetSnapshot,
    ) -> Option<&PhaseAttemptRecord> {
        self.attempts
            .values()
            .filter(|record| selected_record_matches(record, phase, snapshot))
            .max_by_key(|record| self.selection_sort_key(record))
    }

    pub fn phase_was_skipped(&self, phase: WorkflowPhase, snapshot: &PhaseTargetSnapshot) -> bool {
        self.skipped_checkpoints
            .iter()
            .any(|checkpoint| checkpoint.phase == phase && &checkpoint.target_snapshot == snapshot)
    }

    pub fn skipped_phases_for(&self, snapshot: &PhaseTargetSnapshot) -> BTreeSet<WorkflowPhase> {
        self.skipped_checkpoints
            .iter()
            .filter(|checkpoint| &checkpoint.target_snapshot == snapshot)
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
        self.proof_deferrals.iter().any(|record| {
            &record.target_snapshot == snapshot
                && record.finding_scan_id == scan_id
                && deferral_identity_matches(record, fingerprint, identity_id)
        })
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
        let record = self
            .attempts
            .get_mut(&attempt_id)
            .with_context(|| {
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

fn validate_proof_deferral(deferral: &ProofDeferralRecorded) -> Result<()> {
    validate_target_snapshot("proof deferral", &deferral.target_snapshot)?;
    validate_identifier("proof deferral fingerprint", &deferral.finding_fingerprint)?;
    validate_identifier("proof deferral scan id", &deferral.finding_scan_id)?;
    if let Some(identity_id) = deferral.identity_id.as_deref() {
        validate_identifier("proof deferral identity id", identity_id)?;
    }
    let reason = deferral.reason.trim();
    anyhow::ensure!(!reason.is_empty(), "proof deferral reason cannot be blank");
    anyhow::ensure!(reason.len() <= 2_000, "proof deferral reason is too long");
    Ok(())
}

fn unresolved_record_matches(
    record: &PhaseAttemptRecord,
    phase: WorkflowPhase,
    snapshot: &PhaseTargetSnapshot,
) -> bool {
    record.completed.phase == phase
        && &record.completed.target_snapshot == snapshot
        && record.disposition.is_none()
}

fn selected_record_matches(
    record: &PhaseAttemptRecord,
    phase: WorkflowPhase,
    snapshot: &PhaseTargetSnapshot,
) -> bool {
    record.completed.phase == phase
        && &record.completed.target_snapshot == snapshot
        && matches!(
            record.disposition.as_ref().map(|value| &value.disposition),
            Some(PhaseAttemptDisposition::Selected { .. })
        )
}

fn validate_completed(completed: &PhaseAttemptCompleted) -> Result<()> {
    validate_identifier("attempt id", &completed.attempt_id)?;
    anyhow::ensure!(
        !completed.run_refs.is_empty(),
        "phase attempt must reference at least one canonical run"
    );
    for run_ref in &completed.run_refs {
        validate_identifier("run reference", run_ref)?;
    }
    validate_selection_blocker(completed.selection_blocked_reason.as_deref())?;
    anyhow::ensure!(
        completed.selection_blocked_reason.is_none()
            || completed.outcome == PhaseAttemptOutcome::Partial,
        "only a partial phase attempt can carry a selection blocker"
    );
    validate_derivation(completed)?;
    validate_target_snapshot("phase attempt", &completed.target_snapshot)
}

fn validate_selection_blocker(reason: Option<&str>) -> Result<()> {
    let Some(reason) = reason else {
        return Ok(());
    };
    anyhow::ensure!(
        !reason.trim().is_empty(),
        "selection blocker cannot be blank"
    );
    anyhow::ensure!(reason.len() <= 2_000, "selection blocker is too long");
    Ok(())
}

fn validate_derivation(completed: &PhaseAttemptCompleted) -> Result<()> {
    if let Some(parent) = completed.parent_attempt_id.as_deref() {
        validate_identifier("parent attempt id", parent)?;
        anyhow::ensure!(
            completed.derivation != super::PhaseAttemptDerivation::Original,
            "derived phase attempt cannot use original derivation"
        );
        return Ok(());
    }
    anyhow::ensure!(
        completed.derivation == super::PhaseAttemptDerivation::Original,
        "refine/regenerate phase attempt requires a parent attempt id"
    );
    Ok(())
}

fn validate_disposition(
    completed: &PhaseAttemptCompleted,
    disposition: &PhaseAttemptDisposition,
) -> Result<()> {
    let PhaseAttemptDisposition::Selected {
        acknowledged_partial,
    } = disposition
    else {
        return Ok(());
    };
    if let Some(reason) = completed.selection_blocked_reason.as_deref() {
        anyhow::bail!("phase attempt cannot be selected: {reason}");
    }
    match completed.outcome {
        PhaseAttemptOutcome::Completed => anyhow::ensure!(
            !acknowledged_partial,
            "completed attempt does not require partial acknowledgement"
        ),
        PhaseAttemptOutcome::Partial => anyhow::ensure!(
            *acknowledged_partial,
            "partial attempt must be explicitly acknowledged before selection"
        ),
        PhaseAttemptOutcome::Failed | PhaseAttemptOutcome::Canceled => {
            anyhow::bail!("failed or canceled phase attempt cannot be selected")
        }
    }
    Ok(())
}

fn validate_target_snapshot(label: &str, snapshot: &PhaseTargetSnapshot) -> Result<()> {
    anyhow::ensure!(
        !snapshot.target.trim().is_empty(),
        "{label} target snapshot cannot be blank"
    );
    Ok(())
}

fn validate_identifier(label: &str, value: &str) -> Result<()> {
    let value = value.trim();
    anyhow::ensure!(!value.is_empty(), "{label} cannot be blank");
    anyhow::ensure!(value.len() <= 256, "{label} is too long");
    anyhow::ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "{label} contains unsafe characters"
    );
    Ok(())
}
