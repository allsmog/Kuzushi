//! Read-only projection of the existing immutable scan-batch plan.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StudyPlanReceipt {
    pub campaign_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub investigation_id: Option<String>,
    pub plan_path: PathBuf,
    pub plan_sha256: String,
    pub job_count: usize,
    pub workers: usize,
    pub requested_workers: usize,
    pub worker_limitation: Option<String>,
    pub equivalence: BatchEquivalenceKey,
    pub approval_required: bool,
    pub scan_input: Value,
}

/// Authenticate the frozen jobs before exposing them for operator review.
/// This reads the recorded source identity; execution also checks source drift.
pub fn load_study_plan_receipt(root: &Path, id: &str) -> Result<StudyPlanReceipt> {
    let document = super::approved_work::read_bounded_plan(root, id)?;
    let plan = validate_scan_batch_execution_plan(id, &document)?;
    let components = serde_json::from_value(document["equivalence"].clone())?;
    Ok(StudyPlanReceipt {
        campaign_id: plan.batch_id,
        investigation_id: document["investigationId"].as_str().map(str::to_owned),
        plan_path: campaign_plan_path(root, id),
        plan_sha256: super::batch::equivalence::digest_serializable(&document)?,
        job_count: plan.trials_planned,
        workers: plan.effective_workers,
        requested_workers: plan.requested_workers,
        worker_limitation: document["parallelSafety"]["clampReason"]
            .as_str()
            .map(str::to_owned),
        equivalence: BatchEquivalenceKey {
            sha256: plan.equivalence_key,
            components,
        },
        approval_required: document["requiresWorkApproval"] == Value::Bool(true),
        scan_input: plan.base_input,
    })
}

/// Load durable approval and consumption for a draft without opening or
/// migrating the ledger in the presentation layer. Revisions retain spending.
pub fn load_study_allowance(
    root: &Path,
    receipt: &StudyPlanReceipt,
) -> Result<Option<crate::allowance::AllowanceSnapshot>> {
    let db = crate::WorkspaceTarget::new(root)?.findings_db_path();
    let Some(id) = &receipt.investigation_id else {
        return crate::SpendLimiter::read_campaign_allowance(&db, &receipt.campaign_id);
    };
    load_investigation_allowance(root, id)
}

pub(super) fn load_investigation_allowance(root: &Path, id: &str) -> Result<Option<crate::allowance::AllowanceSnapshot>> {
    let db = crate::WorkspaceTarget::new(root)?.findings_db_path();
    match crate::SpendLimiter::read_allowance_snapshot(&db, id) {
        Ok(snapshot) => Ok(Some(snapshot)),
        Err(error)
            if matches!(
                error.downcast_ref::<crate::allowance::AllowanceError>(),
                Some(crate::allowance::AllowanceError::NotApproved(_))
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests;
