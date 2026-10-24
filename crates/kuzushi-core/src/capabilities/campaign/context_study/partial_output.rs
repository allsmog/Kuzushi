//! A partial job may retain an authenticated immutable context for human review.
use super::*;
use crate::capabilities::campaign::snapshot::CampaignJobSnapshot;
use crate::workflow_attempts::{load_map_run_context, PhaseAttemptOutcome};

pub(super) fn eligible(receipt: &ContextStudyReceipt, job: &CampaignJobSnapshot) -> bool {
    receipt.generation_tool == TOOL && matches!(job.state.as_str(), "failed" | "partial")
}

pub(super) fn read(
    root: &Path,
    receipt: &ContextStudyReceipt,
    job: &CampaignJobSnapshot,
) -> Result<GeneratedStudyContext> {
    let run = super::run_result::load(root, job, &receipt.input).with_context(|| {
        format!(
            "Context job {} is {}; partial output cannot be authenticated",
            job.job_id, job.state
        )
    })?;
    anyhow::ensure!(
        run.outcome == PhaseAttemptOutcome::Partial,
        "Context result is not partial"
    );
    let recorded = load_map_run_context(root, std::slice::from_ref(&run.run_id))?
        .context("Partial context job has no authenticated context result")?;
    let output = super::recovery::context_revision_for_run(root, receipt, &run.run_id)?;
    anyhow::ensure!(
        recorded.model_ref.as_ref() == Some(&output.reference),
        "Partial context revision disagrees with its producing run"
    );
    Ok(output)
}
