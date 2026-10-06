//! Review an existing revision through its original authenticated Map run.
use super::*;
use crate::capabilities::threat_model::{load_exact_threat_model, load_threat_model_manifest};
use crate::run_lifecycle::ProjectionHealth;

pub(super) fn review_revision(
    root: &Path,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let reference = requested_revision(input)?;
    let run = producing_run(root, &reference)?;
    let outcome = producing_outcome(root, &run)?;
    let runs = vec![run];
    authenticate_revision(root, &runs, &reference)?;
    anyhow::ensure!(
        !ctx.cancellation.is_some_and(|value| value.is_cancelled()),
        "Map review was canceled."
    );
    anyhow::ensure!(
        crate::workflow_attempts::referenced_runs_match_current_source(root, &runs),
        "Context source changed or cannot be authenticated. Inspect its historical evidence or import verified current-source context before Map review."
    );
    let attempt = super::persist_map_result(root, &runs, outcome, ctx.cancellation)?;
    let summary = "Existing context is ready for Map review. Select it explicitly; partial evidence needs acknowledgement. No jobs or model requests started.";
    Ok(crate::module_result::completed_output_result(
        summary,
        summary,
        json!({"contextOrigin":"revision","attemptId":attempt,
            "runRefs":runs,"modelRef":reference,"mapOutcome":outcome}),
    ))
}

fn requested_revision(input: &Value) -> Result<crate::ThreatModelRef> {
    anyhow::ensure!(
        input.get("campaignId").is_none() && input.get("expectedPlanSha256").is_none(),
        "Choose a context campaign or an exact revision; revision review cannot combine with campaign fields."
    );
    serde_json::from_value(input["threatModelRef"].clone())
        .context("Select an exact immutable threatModelRef for Map review.")
}

fn producing_run(root: &Path, reference: &crate::ThreatModelRef) -> Result<String> {
    load_exact_threat_model(root, reference)?;
    let manifest = load_threat_model_manifest(root)?.context("Context manifest is unavailable.")?;
    let model = manifest
        .models
        .iter()
        .find(|model| model.model_id == reference.model_id)
        .context("Selected context lineage is unavailable.")?;
    let revision = model
        .revisions
        .iter()
        .find(|revision| {
            revision.revision_id == reference.revision_id && revision.sha256 == reference.sha256
        })
        .context("Selected context revision is unavailable.")?;
    revision.run_id.clone().context(
        "This revision has no recorded producing run. Import and verify it against current source before Map review.",
    )
}

fn producing_outcome(root: &Path, run: &str) -> Result<PhaseAttemptOutcome> {
    let projection = crate::run_lifecycle::load_run_projection_unhydrated(root, run)?;
    anyhow::ensure!(
        projection.health == ProjectionHealth::Healthy,
        "Context producing run has damaged evidence. Inspect it before Map review."
    );
    match projection.terminal.as_ref().map(|terminal| terminal.status) {
        Some(RunItemStatus::Completed) => Ok(PhaseAttemptOutcome::Completed),
        Some(RunItemStatus::Partial) => Ok(PhaseAttemptOutcome::Partial),
        _ => anyhow::bail!("Context producing run is not complete or partial. Inspect its recorded outcome before Map review."),
    }
}

fn authenticate_revision(
    root: &Path,
    runs: &[String],
    expected: &crate::ThreatModelRef,
) -> Result<()> {
    let recorded = load_map_run_context(root, runs)?
        .context("Context producing run has no authenticated context result.")?;
    anyhow::ensure!(
        recorded.model_ref.as_ref() == Some(expected),
        "Selected revision disagrees with its producing run. Inspect the original result or import the edited document before Map review."
    );
    Ok(())
}

#[cfg(test)]
mod tests;
