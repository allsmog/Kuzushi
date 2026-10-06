//! Handoff from authenticated batch observations to explicit Scan acceptance.
use super::*;
use crate::findings::{derive_batch_occurrence_report_for_controller, FindingStore};
use crate::run_lifecycle::{RunAttemptId, RunItemStatus};
use crate::workflow_attempts::{
    append_phase_attempt_completed_with_v2, load_phase_attempt_events,
    load_phase_attempt_ledger_v2, PhaseAttemptCompleted, PhaseAttemptLedger, PhaseAttemptOutcome,
    PhaseTargetSnapshot,
};
use crate::WorkflowPhase;

pub fn record_scan_batch_phase_result(
    root: &Path,
    batch_id: &str,
    store: &FindingStore,
) -> Result<Option<String>> {
    let report = derive_batch_occurrence_report_for_controller(root, batch_id, store)?;
    let runs = report.all_attempt_run_ids();
    if runs.is_empty() {
        return Ok(None);
    }
    let outcome = batch_outcome(report.completed, report.planned);
    let blocked = source_selection_block(root, batch_id)?;
    persist_result(root, &runs, outcome, blocked).map(Some)
}

fn batch_outcome(completed: usize, planned: usize) -> PhaseAttemptOutcome {
    if completed == planned && planned > 0 {
        return PhaseAttemptOutcome::Completed;
    }
    if completed > 0 {
        return PhaseAttemptOutcome::Partial;
    }
    PhaseAttemptOutcome::Failed
}

fn source_selection_block(root: &Path, batch_id: &str) -> Result<Option<String>> {
    let plan = super::super::read_json_file(&super::super::campaign_plan_path(root, batch_id))?;
    let expected = plan
        .pointer("/equivalence/workspaceIdentity")
        .and_then(Value::as_str)
        .context("batch has no frozen source identity")?;
    let current = crate::incremental_index::current_workspace_resume_identity(root)?;
    Ok((expected != current).then(||
        "Batch belongs to earlier source content. Keep its observations as history and prepare a current plan before continuing.".into()))
}

fn persist_result(
    root: &Path,
    runs: &[String],
    outcome: PhaseAttemptOutcome,
    blocked: Option<String>,
) -> Result<String> {
    let ledger = PhaseAttemptLedger::from_events(load_phase_attempt_events(root)?)?;
    if let Some(record) = ledger
        .attempts()
        .find(|record| same_result(&record.completed, runs, outcome))
    {
        crate::workflow_attempts::load_phase_attempt_ledger(root)?;
        return Ok(record.completed.attempt_id.clone());
    }
    let attempt = pending_attempt(root, runs, outcome)?;
    let mut completed = PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        runs.to_vec(),
        PhaseTargetSnapshot::capture(root),
        outcome,
    )
    .with_attempt_id(attempt.clone());
    if let Some(reason) = blocked {
        completed = completed.with_selection_blocked(reason);
    }
    append_phase_attempt_completed_with_v2(root, completed)?;
    Ok(attempt)
}

fn same_result(
    completed: &PhaseAttemptCompleted,
    runs: &[String],
    outcome: PhaseAttemptOutcome,
) -> bool {
    completed.phase == WorkflowPhase::Scan
        && completed.run_refs == runs
        && completed.outcome == outcome
}

fn pending_attempt(root: &Path, runs: &[String], outcome: PhaseAttemptOutcome) -> Result<String> {
    let ledger = load_phase_attempt_ledger_v2(root)?;
    anyhow::ensure!(
        ledger.malformed_line.is_none(),
        "Scan history is damaged; restore it before reviewing the batch"
    );
    Ok(ledger
        .attempts
        .values()
        .find(|attempt| {
            attempt.phase == WorkflowPhase::Scan
                && attempt.outcome == outcome_status(outcome)
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

fn outcome_status(outcome: PhaseAttemptOutcome) -> RunItemStatus {
    match outcome {
        PhaseAttemptOutcome::Completed => RunItemStatus::Completed,
        PhaseAttemptOutcome::Partial => RunItemStatus::Partial,
        _ => RunItemStatus::Failed,
    }
}

#[cfg(test)]
mod tests;
