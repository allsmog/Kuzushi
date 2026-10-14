//! Pause finite model work before consuming another job attempt.
use super::*;
use kuzushi_core::allowance::{
    AllowanceError, AllowanceReferenceV1, AllowanceSnapshot, InvestigationWork,
};
use kuzushi_core::{SpendLimiter, WorkspaceTarget};

pub(super) fn stop_reason(
    target: &Path,
    campaign: &str,
    job: &PlanJob,
) -> Result<Option<&'static str>> {
    if job.approved_attempts.is_none() {
        return Ok(None);
    }
    let input: Value = serde_json::from_str(&job.input_json)?;
    if !kuzushi_core::modules::tool_needs_runtime(&job.tool, &input) {
        return Ok(None);
    }
    let reference = job_reference(&input)?;
    let snapshot = campaign_allowance(target, campaign, &reference)?;
    snapshot_stop(&snapshot, &reference)
}

fn job_reference(input: &Value) -> Result<AllowanceReferenceV1> {
    let reference: AllowanceReferenceV1 = serde_json::from_value(
        input
            .get("allowanceRef")
            .context("approved job has no allowance reference")?
            .clone(),
    )?;
    reference.validate()?;
    Ok(reference)
}

fn campaign_allowance(
    target: &Path,
    campaign: &str,
    reference: &AllowanceReferenceV1,
) -> Result<AllowanceSnapshot> {
    let workspace = WorkspaceTarget::new(target)?;
    let snapshot = SpendLimiter::read_campaign_allowance(&workspace.findings_db_path(), campaign)?
        .context("approved campaign allowance is missing; review remaining work")?;
    anyhow::ensure!(
        reference.investigation_id == snapshot.investigation_id,
        "approved job belongs to a different investigation"
    );
    Ok(snapshot)
}

fn snapshot_stop(
    snapshot: &AllowanceSnapshot,
    reference: &AllowanceReferenceV1,
) -> Result<Option<&'static str>> {
    if reference.revision != snapshot.revision {
        return Ok(Some("allowance-revised"));
    }
    // Finite campaign work currently supports Context and Discovery, both
    // protected from consuming the review allocation.
    match snapshot.require_call_capacity(InvestigationWork::Discovery) {
        Ok(()) => Ok(None),
        Err(error)
            if matches!(
                error.downcast_ref::<AllowanceError>(),
                Some(AllowanceError::Exhausted { .. })
            ) =>
        {
            Ok(Some("allowance-exhausted"))
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests;
