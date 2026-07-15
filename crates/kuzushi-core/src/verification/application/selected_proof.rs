use crate::findings::{Finding, FindingStore, PersistedVerification};
use crate::run_artifacts::{load_run_summary, read_run_artifact_text, RunSummary};
use crate::workflow_attempts::{PhaseAttemptCompleted, PhaseAttemptOutcome, PhaseTargetSnapshot};
use crate::{WorkflowPhase, WorkspaceTarget};
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;

#[path = "selected_proof/model_candidate.rs"]
mod model_candidate;

use model_candidate::ModelProofCandidate;

/// Promote one selected Prove attempt from canonical run evidence into durable
/// finding reality. The phase disposition is deliberately owned by the caller
/// and must be recorded only after this function succeeds.
pub fn materialize_selected_proof_attempt(
    workspace: &WorkspaceTarget,
    attempt: &PhaseAttemptCompleted,
) -> Result<usize> {
    validate_attempt(workspace, attempt)?;
    let runs = attempt
        .run_refs
        .iter()
        .map(|run_id| load_verified_run(workspace.root(), run_id, &attempt.target_snapshot))
        .collect::<Result<Vec<_>>>()?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let staged = runs
        .iter()
        .map(|run| stage_proof(workspace, &store, run))
        .collect::<Result<Vec<_>>>()?;
    persist_staged_proofs(&store, staged)
}

struct VerifiedRun {
    summary: RunSummary,
    result: Value,
}

fn stage_proof(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run: &VerifiedRun,
) -> Result<StagedProof> {
    let summary = &run.summary;
    match summary.tool.as_deref() {
        Some("verify:finding") => stage_model_proof(workspace, store, run),
        Some("verify:exploit") => validate_empirical_proof(workspace, store, summary),
        Some(tool) => anyhow::bail!("Prove attempt references unsupported proof tool {tool:?}"),
        None => anyhow::bail!(
            "Prove run {:?} has no canonical tool identity",
            summary.run_id
        ),
    }
}

enum StagedProof {
    Model {
        finding_id: i64,
        record: PersistedVerification,
    },
    AlreadyDurable,
}

fn persist_staged_proofs(store: &FindingStore, staged: Vec<StagedProof>) -> Result<usize> {
    let mut persisted = 0;
    for proof in staged {
        if let StagedProof::Model { finding_id, record } = proof {
            store.save_verification(finding_id, &record)?;
            persisted += 1;
        }
    }
    Ok(persisted)
}

fn validate_attempt(workspace: &WorkspaceTarget, attempt: &PhaseAttemptCompleted) -> Result<()> {
    anyhow::ensure!(
        attempt.phase == WorkflowPhase::Prove,
        "selection is not a Prove attempt"
    );
    anyhow::ensure!(
        attempt.outcome == PhaseAttemptOutcome::Completed,
        "only a completed Prove attempt can be selected"
    );
    anyhow::ensure!(
        attempt.selection_blocked_reason.is_none(),
        "Prove attempt is blocked: {}",
        attempt
            .selection_blocked_reason
            .as_deref()
            .unwrap_or_default()
    );
    anyhow::ensure!(
        !attempt.run_refs.is_empty(),
        "Prove selection has no canonical proof runs"
    );
    let unique = attempt.run_refs.iter().collect::<BTreeSet<_>>();
    anyhow::ensure!(
        unique.len() == attempt.run_refs.len(),
        "Prove selection contains duplicate proof runs"
    );
    let current = PhaseTargetSnapshot::capture(workspace.root());
    anyhow::ensure!(
        attempt.target_snapshot == current,
        "Prove attempt target or revision is stale"
    );
    Ok(())
}

fn load_verified_run(
    target: &std::path::Path,
    run_id: &str,
    expected: &PhaseTargetSnapshot,
) -> Result<VerifiedRun> {
    let summary = load_run_summary(target, run_id)?;
    anyhow::ensure!(
        summary.status == "completed",
        "proof run {run_id:?} is not completed"
    );
    validate_run_snapshot(&summary, expected)?;
    let result = read_json_artifact(target, run_id, "result.json", "proof result")?;
    let digest = crate::run_artifacts::terminal_result_digest("completed", &result);
    anyhow::ensure!(
        summary.terminal_result_sha256.as_deref() == Some(&digest),
        "proof run {run_id:?} result digest does not match run metadata"
    );
    Ok(VerifiedRun { summary, result })
}

fn validate_run_snapshot(summary: &RunSummary, expected: &PhaseTargetSnapshot) -> Result<()> {
    anyhow::ensure!(
        summary.target == expected.target,
        "proof run target does not match the selected target"
    );
    let revision = summary.target_git.as_ref().map(|git| git.sha.as_str());
    let dirty = summary.target_git.as_ref().is_some_and(|git| git.dirty);
    anyhow::ensure!(
        revision == expected.revision.as_deref() && dirty == expected.dirty,
        "proof run revision does not match the selected target snapshot"
    );
    Ok(())
}

fn stage_model_proof(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run: &VerifiedRun,
) -> Result<StagedProof> {
    let candidate = ModelProofCandidate::from_result(&run.result)?;
    let finding =
        current_candidate_finding(store, workspace.root(), &run.summary.run_id, &candidate)?;
    if proof_is_already_materialized(store, &finding, &run.summary.run_id)? {
        return Ok(StagedProof::AlreadyDurable);
    }
    let finding_id = finding
        .id
        .context("selected proof finding has no durable id")?;
    let record = candidate.persisted_record(&run.summary, &run.result)?;
    Ok(StagedProof::Model { finding_id, record })
}

fn validate_empirical_proof(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    summary: &RunSummary,
) -> Result<StagedProof> {
    let input = read_json_artifact(
        workspace.root(),
        &summary.run_id,
        "input.json",
        "proof input",
    )?;
    let reference = required_string(&input, "fingerprint", "proof input fingerprint")?;
    let finding = store
        .get_finding_by_reference(reference)?
        .context("proof finding no longer exists")?;
    let proof = finding
        .verification
        .as_ref()
        .context("empirical proof was not persisted")?;
    anyhow::ensure!(
        proof.verification_run_id.as_deref() == Some(summary.run_id.as_str()),
        "empirical proof does not belong to the selected run"
    );
    anyhow::ensure!(
        proof.is_current_for_scan(finding.scan_id.as_deref()),
        "empirical proof belongs to a stale finding generation"
    );
    Ok(StagedProof::AlreadyDurable)
}

fn current_candidate_finding(
    store: &FindingStore,
    target: &std::path::Path,
    run_id: &str,
    candidate: &ModelProofCandidate,
) -> Result<Finding> {
    let input = read_json_artifact(target, run_id, "input.json", "proof input")?;
    let reference = required_string(&input, "fingerprint", "proof input fingerprint")?;
    let input_finding = store
        .get_finding_by_reference(reference)?
        .context("proof input finding no longer exists")?;
    let finding = store
        .get_finding_by_fingerprint(&candidate.fingerprint)?
        .context("proof result finding no longer exists")?;
    anyhow::ensure!(
        input_finding.id == finding.id,
        "proof input and result identify different findings"
    );
    anyhow::ensure!(
        finding.identity_id == candidate.identity_id,
        "proof identity no longer matches the current finding"
    );
    anyhow::ensure!(
        finding.scan_id.as_deref() == Some(candidate.verified_scan_id.as_str()),
        "proof belongs to a stale finding generation"
    );
    Ok(finding)
}

fn proof_is_already_materialized(
    store: &FindingStore,
    finding: &Finding,
    run_id: &str,
) -> Result<bool> {
    let Some(finding_id) = finding.id else {
        return Ok(false);
    };
    Ok(store
        .get_latest_verification(finding_id)?
        .is_some_and(|proof| {
            proof.verification_run_id.as_deref() == Some(run_id)
                && proof.is_current_for_scan(finding.scan_id.as_deref())
        }))
}

fn read_json_artifact(
    target: &std::path::Path,
    run_id: &str,
    leaf: &str,
    label: &str,
) -> Result<Value> {
    let (_, body) = read_run_artifact_text(target, run_id, leaf).require(label)?;
    serde_json::from_str(&body).with_context(|| format!("{label} is not valid JSON"))
}

fn required_string<'a>(value: &'a Value, key: &str, label: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{label} is missing"))
}

#[cfg(test)]
#[path = "tests/selected_proof.rs"]
mod tests;
