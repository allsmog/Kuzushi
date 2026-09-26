use super::*;
use anyhow::{Context, Result};
use kuzushi_core::workflow_attempts::{
    load_phase_attempt_ledger, PhaseAttemptDisposition, PhaseAttemptOutcome, PhaseTargetSnapshot,
};
use kuzushi_core::{PatchResult, PatchStatus, WorkflowPhase, WorkspaceTarget};
use std::path::Path;

#[derive(Debug, Clone)]
pub(crate) struct DurablePatchSelection {
    pub(crate) attempt_id: String,
    pub(crate) patch: PendingPatch,
}

/// Only a shell-drafted Fix attempt produces a selectable result card; a
/// headless `kuzushi run patch:finding` draft does not.
const NO_FIX_SELECTION_GUIDANCE: &str = "no durable Fix selection; draft one here with `patch <finding>`, then press `u` on its RESULT READY card to Select patch";

pub(crate) fn load_durable_fix_selection(target: &Path) -> Result<DurablePatchSelection> {
    let workspace = WorkspaceTarget::new(target)?;
    let snapshot = PhaseTargetSnapshot::capture(workspace.root());
    let ledger = load_phase_attempt_ledger(workspace.root())?;
    anyhow::ensure!(
        ledger
            .unresolved_for(WorkflowPhase::Fix, &snapshot)
            .is_none(),
        "a newer Fix result is awaiting Select or Discard"
    );
    let record = ledger
        .selected_for(WorkflowPhase::Fix, &snapshot)
        .context(NO_FIX_SELECTION_GUIDANCE)?;
    validate_selected_disposition(record)?;
    let patch = validate_fix_attempt_candidate(&workspace, record)?;
    Ok(DurablePatchSelection {
        attempt_id: record.completed.attempt_id.clone(),
        patch,
    })
}

pub(crate) fn validate_fix_attempt_candidate(
    workspace: &WorkspaceTarget,
    record: &kuzushi_core::workflow_attempts::PhaseAttemptRecord,
) -> Result<PendingPatch> {
    anyhow::ensure!(
        record.completed.phase == WorkflowPhase::Fix,
        "phase attempt is not a Fix result"
    );
    let candidate = selected_attempt_candidate(workspace.root(), &record.completed.run_refs)?;
    persisted_selected_patch(workspace, candidate)
}

fn validate_selected_disposition(
    record: &kuzushi_core::workflow_attempts::PhaseAttemptRecord,
) -> Result<()> {
    let acknowledged_partial = match record.disposition.as_ref().map(|value| &value.disposition) {
        Some(PhaseAttemptDisposition::Selected {
            acknowledged_partial,
        }) => *acknowledged_partial,
        _ => anyhow::bail!("Fix attempt is not selected"),
    };
    anyhow::ensure!(
        record.completed.outcome == PhaseAttemptOutcome::Completed
            || (record.completed.outcome == PhaseAttemptOutcome::Partial && acknowledged_partial),
        "Fix attempt outcome is not eligible for selection"
    );
    Ok(())
}

struct ReferencedPatchCandidate {
    run_id: String,
    result: PatchResult,
    explanation: Option<String>,
}

fn selected_attempt_candidate(
    target: &Path,
    run_refs: &[String],
) -> Result<ReferencedPatchCandidate> {
    let mut candidates = run_refs
        .iter()
        .filter_map(|run_id| patch_candidate_from_run(target, run_id).transpose())
        .collect::<Result<Vec<_>>>()?;
    candidates.sort_by(|left, right| left.result.patch_run_id.cmp(&right.result.patch_run_id));
    candidates.dedup_by(|left, right| left.result.patch_run_id == right.result.patch_run_id);
    anyhow::ensure!(
        candidates.len() == 1,
        "selected Fix attempt must reference exactly one persisted patch candidate; found {}",
        candidates.len()
    );
    Ok(candidates.remove(0))
}

fn patch_candidate_from_run(
    target: &Path,
    run_id: &str,
) -> Result<Option<ReferencedPatchCandidate>> {
    let Ok(summary) = kuzushi_core::load_run_summary(target, run_id) else {
        return Ok(None);
    };
    if !matches!(summary.tool.as_deref(), Some("patch:finding" | "patch:run")) {
        return Ok(None);
    }
    let kuzushi_core::RunArtifactRead::Ready { value, .. } =
        kuzushi_core::read_run_artifact_text(target, run_id, "result.json")
    else {
        anyhow::bail!("selected patch run {run_id:?} has no readable result.json");
    };
    let output: serde_json::Value =
        serde_json::from_str(&value).context("selected patch result is invalid JSON")?;
    let result = serde_json::from_value::<PatchResult>(
        output
            .pointer("/data/patchResult")
            .cloned()
            .context("selected patch result has no typed PatchResult")?,
    )
    .context("selected patch result does not match the PatchResult contract")?;
    let explanation = output
        .pointer("/data/explanation")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    Ok(Some(ReferencedPatchCandidate {
        run_id: run_id.to_string(),
        result,
        explanation,
    }))
}

fn persisted_selected_patch(
    workspace: &WorkspaceTarget,
    candidate: ReferencedPatchCandidate,
) -> Result<PendingPatch> {
    let store = kuzushi_core::FindingStore::open(workspace.findings_db_path())?;
    let persisted = store
        .get_patch_results_for_finding(&candidate.result.fingerprint)?
        .into_iter()
        .find(|result| result.patch_run_id == candidate.result.patch_run_id)
        .context("selected PatchResult is not present in the durable findings store")?;
    ensure_artifact_matches_persisted(&candidate.result, &persisted)?;
    validate_persisted_binding(workspace, &candidate.run_id, &persisted)?;
    pending_patch_from_result(persisted, candidate.explanation.as_deref())
        .context("selected PatchResult has no non-empty diff")
}

fn ensure_artifact_matches_persisted(
    artifact: &PatchResult,
    persisted: &PatchResult,
) -> Result<()> {
    anyhow::ensure!(
        artifact.fingerprint == persisted.fingerprint
            && artifact.diff == persisted.diff
            && artifact.provenance == persisted.provenance,
        "selected run artifact does not match its persisted PatchResult"
    );
    Ok(())
}

fn validate_persisted_binding(
    workspace: &WorkspaceTarget,
    run_id: &str,
    result: &PatchResult,
) -> Result<()> {
    anyhow::ensure!(
        result.status == PatchStatus::Sound,
        "selected patch {} is {}; only SOUND candidates can be applied",
        result.patch_run_id,
        result.status.as_str()
    );
    let provenance = result
        .provenance
        .as_ref()
        .context("selected legacy patch has no source binding; regenerate it")?;
    provenance.ensure_complete_for_apply()?;
    anyhow::ensure!(
        provenance.originating_run_id.as_deref() == Some(run_id),
        "selected patch is not bound to its referenced canonical run"
    );
    let recorded_target = std::fs::canonicalize(&provenance.target)
        .context("selected patch target is unavailable; regenerate it")?;
    anyhow::ensure!(
        recorded_target == workspace.root(),
        "selected patch belongs to another target; regenerate it"
    );
    let store = kuzushi_core::FindingStore::open(workspace.findings_db_path())?;
    let finding = store
        .get_finding_by_fingerprint(&result.fingerprint)?
        .context("selected patch finding is no longer available; regenerate it")?;
    anyhow::ensure!(
        provenance.detector_run_id.as_deref() == finding.scan_id.as_deref(),
        "selected patch belongs to an earlier finding generation; regenerate it"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
