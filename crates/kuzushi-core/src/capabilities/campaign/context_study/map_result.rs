//! Explicit handoff from completed campaign jobs to durable Map review.
use super::*;
use crate::run_lifecycle::RunAttemptId;
use crate::workflow_attempts::{
    append_phase_attempt_completed_with_v2, load_map_run_context, load_phase_attempt_events,
    load_phase_attempt_ledger_v2, PhaseAttemptCompleted, PhaseAttemptDisposition,
    PhaseAttemptLedger, PhaseAttemptOutcome, PhaseTargetSnapshot,
};
use crate::WorkflowPhase;

mod revision;

pub fn execute_context_map(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = ctx
        .workspace
        .context("context Map requires a workspace")?
        .root();
    if input.get("threatModelRef").is_some() {
        return revision::review_revision(root, input, ctx);
    }
    let id = required_text(input, "campaignId")?;
    validate_scan_batch_id(&id)?;
    let directory = campaign_dir(root, &id);
    let _lock = crate::file_lock::ExclusiveFileLock::acquire(&directory.join(".context-map.lock"))?;
    let receipt = load_context_study(root, &id)?;
    ensure_map_generation(&receipt.generation_tool)?;
    anyhow::ensure!(
        input["expectedPlanSha256"] == receipt.plan_sha256,
        "context plan changed; inspect the current plan before reviewing Map"
    );
    let finished = finished_map_runs(root, &receipt)?;
    let runs = finished
        .iter()
        .map(|run| run.run_id.clone())
        .collect::<Vec<_>>();
    let outcome = map_outcome(&finished);
    let reference = authenticated_generated_context(root, &receipt, &runs)?;
    let attempt = persist_map_result(root, &runs, outcome, ctx.cancellation)?;
    let summary = "Recorded Map is ready for inspection. Accept it explicitly before scanning; partial evidence requires acknowledgment. No jobs or model requests started.";
    Ok(crate::module_result::completed_output_result(
        summary,
        summary,
        json!({"campaignId":id,"investigationId":receipt.investigation_id,
            "planSha256":receipt.plan_sha256,"attemptId":attempt,
            "runRefs":runs,"modelRef":reference,"mapOutcome":outcome}),
    ))
}

fn ensure_map_generation(tool: &str) -> Result<()> {
    anyhow::ensure!(
        !matches!(tool, generation::QUESTION_TOOL | generation::PLANNER_TOOL),
        "Question answers and workflow proposals are guidance and cannot complete Map"
    );
    anyhow::ensure!(
        tool != generation::LESSON_TOOL,
        "Lesson drafts are reviewed as lessons and cannot complete Map"
    );
    anyhow::ensure!(
        tool != generation::REGENERATE_TOOL,
        "Regenerated text is an inactive draft. Compare it with its parent. Check the exact revision with threat-model:verify before reviewing the checked revision as Map."
    );
    Ok(())
}

fn finished_map_runs(
    root: &Path,
    receipt: &ContextStudyReceipt,
) -> Result<Vec<super::run_result::ContextRunResult>> {
    anyhow::ensure!(
        crate::incremental_index::current_workspace_resume_identity(root)? == receipt.source_identity,
        "context study belongs to earlier source content; inspect that context or prepare a new Map draft"
    );
    let snapshot = snapshot::load_campaign_snapshot(root, &receipt.campaign_id)?;
    anyhow::ensure!(
        snapshot.jobs.len() == receipt.job_count(),
        "context study job count changed"
    );
    let planned = preparation::plan_jobs(
        receipt.input.clone(),
        &receipt.preparation_jobs,
        &receipt.generation_tool,
    );
    snapshot
        .jobs
        .iter()
        .map(|job| {
            let expected = planned
                .iter()
                .find(|row| row["jobId"].as_str() == Some(&job.job_id))
                .context("Map job is absent from its frozen plan")?;
            super::run_result::load(root, job, &expected["input"])
        })
        .collect()
}

fn map_outcome(runs: &[super::run_result::ContextRunResult]) -> PhaseAttemptOutcome {
    if runs
        .iter()
        .any(|run| run.outcome == PhaseAttemptOutcome::Partial)
    {
        return PhaseAttemptOutcome::Partial;
    }
    PhaseAttemptOutcome::Completed
}

fn authenticated_generated_context(
    root: &Path,
    receipt: &ContextStudyReceipt,
    runs: &[String],
) -> Result<crate::ThreatModelRef> {
    let expected = receipt
        .generated_context(root)?
        .context("context job has no completed result")?;
    let recorded = load_map_run_context(root, runs)?
        .context("Map runs have no authenticated context result")?;
    anyhow::ensure!(
        recorded.model_ref.as_ref() == Some(&expected),
        "generated context disagrees with its authenticated run result"
    );
    anyhow::ensure!(
        runs.last() == Some(&recorded.run_id),
        "context result does not belong to the generation job"
    );
    Ok(expected)
}

fn persist_map_result(
    root: &Path,
    runs: &[String],
    outcome: PhaseAttemptOutcome,
    cancellation: Option<&crate::ScanCancellation>,
) -> Result<String> {
    let lock = crate::workspace::workspace_state_dir(root).join(".context-map.lock");
    let _lock = crate::file_lock::ExclusiveFileLock::acquire_cancellable(&lock, &|| {
        cancellation.is_some_and(|value| value.is_cancelled())
    })?;
    let ledger = PhaseAttemptLedger::from_events(load_phase_attempt_events(root)?)?;
    if let Some(record) = ledger.attempts().find(|record| {
        record.completed.phase == WorkflowPhase::Map && record.completed.run_refs == runs
    }) {
        crate::workflow_attempts::load_phase_attempt_ledger(root)?;
        anyhow::ensure!(
            !matches!(record.disposition.as_ref().map(|value| &value.disposition), Some(PhaseAttemptDisposition::Discarded)),
            "this Map result was discarded; inspect its recorded runs or approve a new context draft"
        );
        return Ok(record.completed.attempt_id.clone());
    }
    let attempt = pending_map_attempt(root, runs)?;
    let completed = PhaseAttemptCompleted::new(
        WorkflowPhase::Map,
        runs.to_vec(),
        PhaseTargetSnapshot::capture(root),
        outcome,
    )
    .with_attempt_id(attempt.clone());
    append_phase_attempt_completed_with_v2(root, completed)?;
    Ok(attempt)
}

/// Reuse a typed receipt if interruption happened before its compatibility append.
fn pending_map_attempt(root: &Path, runs: &[String]) -> Result<String> {
    let ledger = load_phase_attempt_ledger_v2(root)?;
    anyhow::ensure!(
        ledger.malformed_line.is_none(),
        "Map history is damaged; inspect it before reviewing context"
    );
    Ok(ledger
        .attempts
        .values()
        .find(|attempt| {
            attempt.phase == WorkflowPhase::Map
                && attempt
                    .run_refs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    == runs
        })
        .map(|attempt| attempt.attempt_id.to_string())
        .unwrap_or_else(|| RunAttemptId::new().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_drafts_keep_their_own_review_contracts() {
        assert!(ensure_map_generation(TOOL).is_ok());
        assert!(ensure_map_generation(generation::LESSON_TOOL).is_err());
        assert!(ensure_map_generation(generation::PLANNER_TOOL).is_err());
        let error = ensure_map_generation(generation::REGENERATE_TOOL).unwrap_err();
        assert!(error.to_string().contains("Check the exact revision"));
    }
}
