//! Read accounting for an exact saved plan without approving or preparing work.
use super::*;
use crate::allowance::{AllowanceSnapshot, CampaignAllowanceReport};

const FIXED_KINDS: [&str; 5] = [
    SCAN_BATCH_KIND,
    CONTEXT_MATRIX_KIND,
    SCOPE_STUDY_KIND,
    REVIEW_STUDY_KIND,
    "context-study",
];

pub fn is_fixed_study_kind(kind: Option<&str>) -> bool {
    kind.is_some_and(|kind| FIXED_KINDS.contains(&kind))
}

/// Charges remain readable when source evidence is unavailable or newer work
/// shares the investigation. This projection never grants execution authority.
pub fn load_fixed_study_allowance(
    root: &Path,
    id: &str,
    digest: &str,
) -> Result<Option<AllowanceSnapshot>> {
    let plan = approved_work::read_bounded_plan(root, id)?;
    validate_identity(&plan, id, digest)?;
    let workspace = crate::WorkspaceTarget::new(root)?;
    let report =
        crate::SpendLimiter::read_campaign_allowance_report(&workspace.findings_db_path(), id)?;
    if let Some(report) = report {
        validate_approval(&plan, id, digest, &report)?;
        return Ok(Some(report.current_investigation));
    }
    match declared_investigation(&plan)? {
        Some(id) => study_receipt::load_investigation_allowance(root, id),
        None => Ok(None),
    }
}

fn validate_identity(plan: &Value, id: &str, digest: &str) -> Result<()> {
    anyhow::ensure!(
        batch::equivalence::digest_serializable(plan)? == digest,
        "Study plan changed; refresh its recorded history before reading allowance"
    );
    anyhow::ensure!(
        is_fixed_study_kind(plan["kind"].as_str()),
        "Selected plan is not a bounded study"
    );
    anyhow::ensure!(
        plan["schemaVersion"] == 1
            && plan["campaignId"] == id
            && plan["requiresWorkApproval"] == true,
        "Study identity or work approval requirement is invalid"
    );
    let jobs = plan["jobs"]
        .as_array()
        .context("Study has no recorded jobs")?;
    anyhow::ensure!(
        (1..=100).contains(&jobs.len()),
        "Study must contain one to 100 fixed jobs"
    );
    Ok(())
}

fn validate_approval(
    plan: &Value,
    id: &str,
    digest: &str,
    report: &CampaignAllowanceReport,
) -> Result<()> {
    let work = report
        .approval
        .work_plan
        .as_ref()
        .context("Study approval has no fixed work plan")?;
    anyhow::ensure!(
        work.campaign_id == id && work.plan_sha256 == digest,
        "Study differs from its recorded work approval"
    );
    anyhow::ensure!(
        Some(work.jobs.len()) == plan["jobs"].as_array().map(Vec::len),
        "Study workload differs from its recorded approval"
    );
    if let Some(declared) = declared_investigation(plan)? {
        anyhow::ensure!(
            declared == report.approval.investigation_id,
            "Study names a different investigation than its recorded approval"
        );
    }
    Ok(())
}

fn declared_investigation(plan: &Value) -> Result<Option<&str>> {
    match plan.get("investigationId") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .context("Study investigation identity is malformed")
            .map(Some),
    }
}

#[cfg(test)]
mod tests;
