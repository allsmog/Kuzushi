//! Authenticate finished Map jobs without changing their recorded queue state.
use super::*;
use crate::capabilities::campaign::snapshot::CampaignJobSnapshot;
use crate::run_lifecycle::{CallKind, ProjectionHealth, RunItemStatus, RunProjection};
use crate::workflow_attempts::PhaseAttemptOutcome;

pub(super) struct ContextRunResult {
    pub run_id: String,
    pub outcome: PhaseAttemptOutcome,
}

pub(super) fn load(
    root: &Path,
    job: &CampaignJobSnapshot,
    expected_input: &Value,
) -> Result<ContextRunResult> {
    let expected = expected_status(job)?;
    let run = job
        .run_id
        .as_deref()
        .context("Finished Map job has no run identity")?;
    let projection = crate::run_lifecycle::load_run_projection_unhydrated(root, run)?;
    require_matching_call(&projection, job, expected)?;
    let input = crate::run_artifacts::load_authenticated_run_input(root, run)?;
    anyhow::ensure!(
        super::super::work_input_digest(&input)?
            == super::super::work_input_digest(expected_input)?,
        "Map job input differs from its frozen context plan"
    );
    Ok(ContextRunResult {
        run_id: run.into(),
        outcome: if expected == RunItemStatus::Partial {
            PhaseAttemptOutcome::Partial
        } else {
            PhaseAttemptOutcome::Completed
        },
    })
}

fn expected_status(job: &CampaignJobSnapshot) -> Result<RunItemStatus> {
    match job.state.as_str() {
        "completed" => Ok(RunItemStatus::Completed),
        "failed" | "partial" => Ok(RunItemStatus::Partial),
        _ => anyhow::bail!(
            "Map job {} is {}; inspect its outcome before reviewing Map",
            job.job_id,
            job.state
        ),
    }
}

fn require_matching_call(
    projection: &RunProjection,
    job: &CampaignJobSnapshot,
    expected: RunItemStatus,
) -> Result<()> {
    anyhow::ensure!(
        projection.health == ProjectionHealth::Healthy,
        "Map job has damaged run evidence"
    );
    anyhow::ensure!(
        projection
            .terminal
            .as_ref()
            .is_some_and(|terminal| terminal.status == expected),
        "Map job {} is {}; no matching finished run outcome",
        job.job_id,
        job.state
    );
    anyhow::ensure!(
        projection
            .calls
            .values()
            .any(|call| call.kind == CallKind::Tool
                && Some(call.label.as_str()) == job.tool.as_deref()
                && call.status == expected),
        "Map job {} is {}; no matching finished tool call",
        job.job_id,
        job.state
    );
    Ok(())
}
