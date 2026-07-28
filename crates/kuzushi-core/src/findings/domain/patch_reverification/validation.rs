use super::super::{PatchLifecycleRecord, PatchLifecycleState, PersistedSandboxBackend};
use super::{
    PatchDetectorReplayOutcome, PatchEmpiricalOutcome, PatchReverificationCaseKind,
    PatchReverificationFileHash, PatchReverificationReceipt, PatchReverificationStep,
    PatchReverificationTarget, MAX_RECEIPT_STEPS, PATCH_REVERIFICATION_RECEIPT_SCHEMA_VERSION,
};
use crate::content_store::{ObjectKind, ObjectRef, MAX_CONTENT_OBJECT_BYTES};
use crate::identity::Blake3Hash;
use anyhow::Result;
use std::collections::BTreeSet;

pub(super) fn validate(receipt: &PatchReverificationReceipt) -> Result<()> {
    anyhow::ensure!(
        receipt.schema_version == PATCH_REVERIFICATION_RECEIPT_SCHEMA_VERSION,
        "unsupported patch reverification receipt schema version"
    );
    validate_bindings(receipt)?;
    anyhow::ensure!(
        receipt.source_identity.permits_cross_attempt_reuse(),
        "receipt source identity is not reusable"
    );
    validate_proof_snapshot_ref(&receipt.reproducer)?;
    validate_steps(&receipt.steps)?;
    validate_file_hashes(&receipt.start_touched_files)?;
    validate_file_hashes(&receipt.end_touched_files)?;
    anyhow::ensure!(
        touched_paths(&receipt.start_touched_files).eq(touched_paths(&receipt.end_touched_files)),
        "receipt start/end touched-file sets differ"
    );
    Ok(())
}

fn validate_bindings(receipt: &PatchReverificationReceipt) -> Result<()> {
    for (label, value) in [
        ("application id", receipt.application_id.as_str()),
        ("patch run id", receipt.patch_run_id.as_str()),
        ("reverify run id", receipt.reverify_run_id.as_str()),
        ("source commit", receipt.source_commit.as_str()),
        ("diff hash", receipt.diff_hash.as_str()),
        ("detector tool", receipt.detector_tool.as_str()),
        ("detector run id", receipt.detector_run_id.as_str()),
    ] {
        anyhow::ensure!(
            !value.trim().is_empty() && value.len() <= 4096,
            "receipt {label} is empty or oversized"
        );
    }
    Ok(())
}

fn validate_steps(steps: &[PatchReverificationStep]) -> Result<()> {
    anyhow::ensure!(
        steps.len() <= MAX_RECEIPT_STEPS,
        "receipt has too many empirical steps"
    );
    for step in steps {
        anyhow::ensure!(
            !step.case_id.trim().is_empty() && step.case_id.len() <= 64,
            "receipt case id is empty or oversized"
        );
        Blake3Hash::new(step.input_digest.clone())?;
    }
    Ok(())
}

fn validate_file_hashes(files: &[PatchReverificationFileHash]) -> Result<()> {
    anyhow::ensure!(files.len() <= 256, "receipt has too many touched files");
    for file in files {
        anyhow::ensure!(
            !file.path.trim().is_empty() && file.path.len() <= 4096,
            "receipt touched path is empty or oversized"
        );
        if let Some(hash) = &file.hash {
            Blake3Hash::new(hash.clone())?;
        }
    }
    Ok(())
}

pub(crate) fn validate_proof_snapshot_ref(object_ref: &ObjectRef) -> Result<()> {
    anyhow::ensure!(
        object_ref.kind == ObjectKind::ProofSnapshot,
        "evidence object is not a proof snapshot"
    );
    Blake3Hash::new(object_ref.hash.as_str().to_string())?;
    anyhow::ensure!(
        object_ref.size_bytes <= MAX_CONTENT_OBJECT_BYTES,
        "evidence object exceeds the CAS object limit"
    );
    Ok(())
}

pub(super) fn validate_for_verified(receipt: &PatchReverificationReceipt) -> Result<()> {
    validate(receipt)?;
    validate_verified_metadata(receipt)?;
    anyhow::ensure!(
        receipt.steps.iter().all(is_trusted_step),
        "verified receipt contains an untrusted empirical step"
    );
    let case_ids = validated_case_ids(&receipt.steps)?;
    validate_bound_case_pairs(&receipt.steps, &case_ids)?;
    validate_required_case_targets(&receipt.steps)?;
    anyhow::ensure!(
        receipt.steps.iter().all(empirical_outcome_is_valid),
        "verified receipt empirical outcomes do not satisfy the attack ladder"
    );
    Ok(())
}

fn validate_verified_metadata(receipt: &PatchReverificationReceipt) -> Result<()> {
    anyhow::ensure!(
        receipt.detector_outcome == PatchDetectorReplayOutcome::NotRediscovered,
        "verified receipt did not complete a clean detector replay"
    );
    anyhow::ensure!(
        receipt.start_touched_files == receipt.end_touched_files,
        "verified receipt touched-file hashes changed during reverification"
    );
    anyhow::ensure!(
        (6..=MAX_RECEIPT_STEPS).contains(&receipt.steps.len())
            && receipt.steps.len().is_multiple_of(2),
        "verified receipt has an invalid empirical step count"
    );
    Ok(())
}

fn is_trusted_step(step: &PatchReverificationStep) -> bool {
    step.passed && step.reached_sink && step.backend == PersistedSandboxBackend::Bwrap
}

fn validated_case_ids<'a>(steps: &'a [PatchReverificationStep]) -> Result<BTreeSet<&'a str>> {
    let originals = case_ids(steps, PatchReverificationCaseKind::OriginalAttack);
    let controls = case_ids(steps, PatchReverificationCaseKind::BenignControl);
    let variants = case_ids(steps, PatchReverificationCaseKind::Variant);
    anyhow::ensure!(
        originals.len() == 1 && controls.len() == 1 && (1..=3).contains(&variants.len()),
        "verified receipt has an invalid case-role count"
    );
    let all_ids = originals
        .iter()
        .copied()
        .chain(controls.iter().copied())
        .chain(variants.iter().copied())
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        all_ids.len() == originals.len() + controls.len() + variants.len(),
        "verified receipt reuses a case id across roles"
    );
    Ok(all_ids)
}

fn case_ids(
    steps: &[PatchReverificationStep],
    kind: PatchReverificationCaseKind,
) -> BTreeSet<&str> {
    steps
        .iter()
        .filter(|step| step.case_kind == kind)
        .map(|step| step.case_id.as_str())
        .collect()
}

fn validate_bound_case_pairs(
    steps: &[PatchReverificationStep],
    case_ids: &BTreeSet<&str>,
) -> Result<()> {
    for case_id in case_ids {
        let case_steps = steps
            .iter()
            .filter(|step| step.case_id.as_str() == *case_id)
            .collect::<Vec<_>>();
        anyhow::ensure!(
            is_bound_case_pair(&case_steps),
            "verified receipt does not contain one bound vulnerable/patched pair per case"
        );
    }
    Ok(())
}

fn is_bound_case_pair(steps: &[&PatchReverificationStep]) -> bool {
    steps.len() == 2
        && steps
            .iter()
            .filter(|step| step.target == PatchReverificationTarget::Vulnerable)
            .count()
            == 1
        && steps
            .iter()
            .filter(|step| step.target == PatchReverificationTarget::Patched)
            .count()
            == 1
        && steps[0].input_digest == steps[1].input_digest
        && steps[0].backend == steps[1].backend
}

fn validate_required_case_targets(steps: &[PatchReverificationStep]) -> Result<()> {
    for kind in [
        PatchReverificationCaseKind::OriginalAttack,
        PatchReverificationCaseKind::BenignControl,
        PatchReverificationCaseKind::Variant,
    ] {
        for target in [
            PatchReverificationTarget::Vulnerable,
            PatchReverificationTarget::Patched,
        ] {
            anyhow::ensure!(
                steps
                    .iter()
                    .any(|step| step.case_kind == kind && step.target == target),
                "verified receipt is missing a required empirical case"
            );
        }
    }
    Ok(())
}

fn empirical_outcome_is_valid(step: &PatchReverificationStep) -> bool {
    match (step.case_kind, step.target) {
        (PatchReverificationCaseKind::BenignControl, _) => {
            step.outcome == PatchEmpiricalOutcome::CleanExit
        }
        (_, PatchReverificationTarget::Vulnerable) => {
            step.outcome == PatchEmpiricalOutcome::Exploited
        }
        (_, PatchReverificationTarget::Patched) => step.outcome == PatchEmpiricalOutcome::CleanExit,
    }
}

pub(super) fn validate_for_record(
    receipt: &PatchReverificationReceipt,
    record: &PatchLifecycleRecord,
) -> Result<()> {
    validate(receipt)?;
    anyhow::ensure!(
        receipt.application_id == record.application_id,
        "receipt application mismatch"
    );
    anyhow::ensure!(
        receipt.patch_run_id == record.patch_run_id,
        "receipt patch run mismatch"
    );
    validate_record_provenance(receipt, record)?;
    anyhow::ensure!(
        touched_paths(&receipt.start_touched_files).eq(record.touched_paths()),
        "receipt touched-file set does not match the patch application"
    );
    if record.state == PatchLifecycleState::Verified {
        validate_for_verified(receipt)?;
    }
    Ok(())
}

fn validate_record_provenance(
    receipt: &PatchReverificationReceipt,
    record: &PatchLifecycleRecord,
) -> Result<()> {
    anyhow::ensure!(
        record.reverify_run_id.as_deref() == Some(receipt.reverify_run_id.as_str()),
        "receipt reverify run mismatch"
    );
    anyhow::ensure!(
        record.base_commit.as_deref() == Some(receipt.source_commit.as_str()),
        "receipt source commit mismatch"
    );
    anyhow::ensure!(
        receipt.diff_hash == record.diff_hash,
        "receipt diff mismatch"
    );
    Ok(())
}

fn touched_paths(files: &[PatchReverificationFileHash]) -> impl Iterator<Item = &str> {
    files.iter().map(|file| file.path.as_str())
}
