use super::ladder::{run_case_ladder, LadderEvaluation};
use super::EmpiricalCaseRunner;
use crate::findings::{
    Finding, PatchDetectorReplayOutcome, PatchLifecycleRecord, PatchLifecycleState, PatchResult,
    PatchReverificationReceipt, PersistedProofVerdict, PersistedSandboxBackend,
    PersistedVerification, PATCH_REVERIFICATION_RECEIPT_SCHEMA_VERSION,
};
use crate::remediation::patch::{
    hash_optional_file, patch_diff_hash, run_git_with_input, unattended_patch_control,
    with_disposable_worktree,
};
use crate::verification::{load_empirical_reproducer, EmpiricalReproducerSnapshot};
use crate::workflow_attempts::TargetContentIdentity;
use anyhow::{Context, Result};
use std::path::Path;

const EMPIRICAL_CASE_TIMEOUT_MS: u64 = 30_000;
const EMPIRICAL_AGGREGATE_TIMEOUT_MS: u64 = 180_000;

pub(crate) struct EmpiricalLadderRun {
    pub(crate) terminal_state: Option<PatchLifecycleState>,
    pub(crate) receipt: PatchReverificationReceipt,
}

pub(crate) fn prepare_empirical_ladder(
    store: &crate::findings::FindingStore,
    target: &Path,
    record: &PatchLifecycleRecord,
    detector_tool: &str,
    detector_run_id: &str,
    runner: &dyn EmpiricalCaseRunner,
) -> Result<Option<EmpiricalLadderRun>> {
    let patch = originating_patch(store, record)?;
    let Some(binding) = empirical_binding(&patch) else {
        return Ok(None);
    };
    let finding = bound_finding(store, record, &binding)?;
    let source_commit = bound_source_commit(record, binding.source_commit)?;
    let diff = bound_patch_diff(record, &patch)?;
    let snapshot = bound_reproducer(target, &finding, &binding)?;
    let start_touched_files = super::active_touched_hashes(target, record)?;
    let reverify_run_id = required_reverify_run_id(record)?;
    let evaluation = evaluate_ladder(target, record, &binding, &finding, diff, &snapshot, runner)?;
    Ok(Some(build_ladder_run(
        record,
        binding,
        detector_tool,
        detector_run_id,
        source_commit,
        reverify_run_id,
        start_touched_files,
        evaluation,
    )))
}

struct EmpiricalBinding<'a> {
    reproducer: &'a crate::content_store::ObjectRef,
    source_identity: &'a TargetContentIdentity,
    verification_run_id: &'a str,
    source_commit: &'a str,
}

fn empirical_binding(patch: &PatchResult) -> Option<EmpiricalBinding<'_>> {
    let provenance = patch.provenance.as_ref()?;
    Some(EmpiricalBinding {
        reproducer: provenance.reproducer.as_ref()?,
        source_identity: provenance.verification_source_identity.as_ref()?,
        verification_run_id: provenance.verification_run_id.as_deref()?,
        source_commit: &provenance.source_commit,
    })
}

fn originating_patch(
    store: &crate::findings::FindingStore,
    record: &PatchLifecycleRecord,
) -> Result<PatchResult> {
    store
        .get_patch_results_for_finding(&record.fingerprint)?
        .into_iter()
        .find(|patch| patch.patch_run_id == record.patch_run_id)
        .context("the originating patch result is unavailable")
}

fn bound_finding(
    store: &crate::findings::FindingStore,
    record: &PatchLifecycleRecord,
    binding: &EmpiricalBinding<'_>,
) -> Result<Finding> {
    let finding = store
        .get_finding_by_fingerprint(&record.fingerprint)?
        .context("the originating finding is unavailable")?;
    let verification = finding
        .verification
        .as_ref()
        .context("the originating empirical verification is unavailable")?;
    validate_verification(record, &finding, verification, binding)?;
    Ok(finding)
}

fn validate_verification(
    record: &PatchLifecycleRecord,
    finding: &Finding,
    verification: &PersistedVerification,
    binding: &EmpiricalBinding<'_>,
) -> Result<()> {
    anyhow::ensure!(
        record.finding_scan_id == finding.scan_id
            && verification.is_current_for_scan(finding.scan_id.as_deref())
            && verification.verification_run_id.as_deref() == Some(binding.verification_run_id)
            && verification.proof_verdict == PersistedProofVerdict::Exploited
            && verification.provenance.as_ref().is_some_and(|current| {
                current.reproducer.as_ref() == Some(binding.reproducer)
                    && current.source_identity == *binding.source_identity
            }),
        "the finding's empirical verification no longer matches patch provenance"
    );
    anyhow::ensure!(
        verification.backend == PersistedSandboxBackend::Bwrap,
        "the originating empirical verification did not use the supported Bwrap backend"
    );
    Ok(())
}

fn bound_source_commit<'a>(
    record: &'a PatchLifecycleRecord,
    provenance_commit: &str,
) -> Result<&'a str> {
    let source_commit = record
        .base_commit
        .as_deref()
        .context("patch application has no exact base commit")?;
    anyhow::ensure!(
        provenance_commit == source_commit,
        "patch application base commit does not match patch provenance"
    );
    Ok(source_commit)
}

fn bound_patch_diff<'a>(record: &PatchLifecycleRecord, patch: &'a PatchResult) -> Result<&'a str> {
    let diff = patch
        .diff
        .as_deref()
        .context("the originating patch diff is unavailable")?;
    anyhow::ensure!(
        patch_diff_hash(diff) == record.diff_hash,
        "the originating patch diff no longer matches the application"
    );
    Ok(diff)
}

fn bound_reproducer(
    target: &Path,
    finding: &Finding,
    binding: &EmpiricalBinding<'_>,
) -> Result<EmpiricalReproducerSnapshot> {
    let snapshot = load_empirical_reproducer(target, binding.reproducer)?;
    let language = finding
        .verification
        .as_ref()
        .and_then(|verification| verification.language.as_deref());
    anyhow::ensure!(
        language == Some(snapshot.language.as_str()),
        "empirical reproducer language does not match verification provenance"
    );
    Ok(snapshot)
}

fn required_reverify_run_id(record: &PatchLifecycleRecord) -> Result<&str> {
    record
        .reverify_run_id
        .as_deref()
        .context("empirical patch reverification has no run id")
}

fn evaluate_ladder(
    target: &Path,
    record: &PatchLifecycleRecord,
    binding: &EmpiricalBinding<'_>,
    finding: &Finding,
    diff: &str,
    snapshot: &EmpiricalReproducerSnapshot,
    runner: &dyn EmpiricalCaseRunner,
) -> Result<LadderEvaluation> {
    let control = unattended_patch_control();
    with_disposable_worktree(target, binding.source_commit, control, |vulnerable| {
        ensure_source_identity(binding.source_identity, binding.source_commit, vulnerable)?;
        ensure_checkout_hashes(vulnerable, record, false)?;
        with_disposable_worktree(target, binding.source_commit, control, |patched| {
            run_git_with_input(patched, &["apply"], diff, control)
                .context("could not apply the bound patch in its disposable empirical tree")?;
            ensure_checkout_hashes(patched, record, true)?;
            Ok(run_case_ladder(
                runner,
                vulnerable,
                patched,
                finding,
                finding
                    .verification
                    .as_ref()
                    .expect("checked verification")
                    .backend,
                &snapshot.cases,
                EMPIRICAL_CASE_TIMEOUT_MS,
                EMPIRICAL_AGGREGATE_TIMEOUT_MS,
            ))
        })
    })
}

#[allow(clippy::too_many_arguments)]
fn build_ladder_run(
    record: &PatchLifecycleRecord,
    binding: EmpiricalBinding<'_>,
    detector_tool: &str,
    detector_run_id: &str,
    source_commit: &str,
    reverify_run_id: &str,
    start_touched_files: Vec<crate::findings::PatchReverificationFileHash>,
    evaluation: LadderEvaluation,
) -> EmpiricalLadderRun {
    EmpiricalLadderRun {
        terminal_state: evaluation.terminal_state,
        receipt: PatchReverificationReceipt {
            schema_version: PATCH_REVERIFICATION_RECEIPT_SCHEMA_VERSION,
            application_id: record.application_id.clone(),
            patch_run_id: record.patch_run_id.clone(),
            reverify_run_id: reverify_run_id.to_string(),
            source_identity: binding.source_identity.clone(),
            source_commit: source_commit.to_string(),
            diff_hash: record.diff_hash.clone(),
            reproducer: binding.reproducer.clone(),
            steps: evaluation.steps,
            detector_tool: detector_tool.to_string(),
            detector_run_id: detector_run_id.to_string(),
            detector_outcome: PatchDetectorReplayOutcome::NotRun,
            start_touched_files,
            end_touched_files: Vec::new(),
        },
    }
}

fn ensure_source_identity(
    identity: &TargetContentIdentity,
    source_commit: &str,
    checkout: &Path,
) -> Result<()> {
    match identity {
        TargetContentIdentity::IndexedSnapshot {
            tree_hash: Some(expected),
            ..
        } => ensure_indexed_tree_hash(checkout, expected.as_str())?,
        TargetContentIdentity::CleanGitCommit { commit } => anyhow::ensure!(
            commit.as_str() == source_commit,
            "empirical verification commit does not match patch source commit"
        ),
        _ => anyhow::bail!("empirical verification source identity is incomplete"),
    }
    Ok(())
}

fn ensure_indexed_tree_hash(checkout: &Path, expected: &str) -> Result<()> {
    let actual = crate::incremental_index::current_workspace_tree_hash(checkout)?;
    anyhow::ensure!(
        actual.as_str() == expected,
        "empirical vulnerable checkout does not match verification source identity"
    );
    Ok(())
}

fn ensure_checkout_hashes(
    checkout: &Path,
    record: &PatchLifecycleRecord,
    patched: bool,
) -> Result<()> {
    for file in &record.touched_files {
        let actual = hash_optional_file(checkout, Path::new(&file.path))?;
        let expected = if patched {
            &file.after_hash
        } else {
            &file.before_hash
        };
        anyhow::ensure!(
            &actual == expected,
            "disposable empirical checkout does not match stored touched-file hashes"
        );
    }
    Ok(())
}
