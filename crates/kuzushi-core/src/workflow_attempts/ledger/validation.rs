use super::{
    PhaseAttemptCompleted, PhaseAttemptDisposition, PhaseAttemptOutcome, PhaseTargetSnapshot,
    ProofDeferralRecorded,
};
use crate::workflow_attempts::PhaseAttemptDerivation;
use anyhow::Result;

pub(super) fn validate_proof_deferral(deferral: &ProofDeferralRecorded) -> Result<()> {
    validate_target_snapshot("proof deferral", &deferral.target_snapshot)?;
    validate_finding_fingerprint("proof deferral fingerprint", &deferral.finding_fingerprint)?;
    validate_identifier("proof deferral scan id", &deferral.finding_scan_id)?;
    if let Some(identity_id) = deferral.identity_id.as_deref() {
        validate_identifier("proof deferral identity id", identity_id)?;
    }
    let reason = deferral.reason.trim();
    anyhow::ensure!(!reason.is_empty(), "proof deferral reason cannot be blank");
    anyhow::ensure!(reason.len() <= 2_000, "proof deferral reason is too long");
    Ok(())
}

pub(super) fn validate_completed(completed: &PhaseAttemptCompleted) -> Result<()> {
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
            completed.derivation != PhaseAttemptDerivation::Original,
            "derived phase attempt cannot use original derivation"
        );
        return Ok(());
    }
    anyhow::ensure!(
        completed.derivation == PhaseAttemptDerivation::Original,
        "refine/regenerate phase attempt requires a parent attempt id"
    );
    Ok(())
}

pub(super) fn validate_disposition(
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

pub(super) fn validate_target_snapshot(label: &str, snapshot: &PhaseTargetSnapshot) -> Result<()> {
    anyhow::ensure!(
        !snapshot.target.trim().is_empty(),
        "{label} target snapshot cannot be blank"
    );
    Ok(())
}

/// Finding fingerprints are `tool:rule:hash` — the `:` separator is part of
/// the durable identity, so the plain identifier alphabet rejects EVERY real
/// fingerprint (which made proof deferral impossible outside fixtures).
fn validate_finding_fingerprint(label: &str, value: &str) -> Result<()> {
    let value = value.trim();
    anyhow::ensure!(!value.is_empty(), "{label} cannot be blank");
    anyhow::ensure!(value.len() <= 256, "{label} is too long");
    anyhow::ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')),
        "{label} contains unsafe characters"
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
