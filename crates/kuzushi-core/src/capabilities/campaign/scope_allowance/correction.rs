//! Manual correction keeps the investigation that paid for the failed proposal.
use super::*;
use crate::workspace::ScanScopeCorrection;

pub(super) fn load(
    root: &Path,
    workspace: &WorkspaceTarget,
    review: &ScanScopeReview,
    correction: &ScanScopeCorrection,
) -> Result<crate::allowance::AllowanceSnapshot> {
    let receipt = authenticated_study(root, correction)?;
    require_original_proposal(workspace, review, &receipt)?;
    let output = receipt
        .rejected_scope_draft(root)?
        .context("scope correction's rejected output is missing; restore its history")?;
    anyhow::ensure!(
        output.reference == correction.rejected,
        "scope correction references different rejected output"
    );
    let snapshot = crate::run_artifacts::load_investigation_allowance_for_runs(
        root,
        std::slice::from_ref(&correction.rejected.run_id),
    )?
    .context("scope correction accounting is missing; restore it before planning work")?;
    anyhow::ensure!(
        snapshot.investigation_id == receipt.investigation_id,
        "scope correction accounting belongs to a different investigation"
    );
    Ok(snapshot)
}

fn authenticated_study(
    root: &Path,
    correction: &ScanScopeCorrection,
) -> Result<ContextStudyReceipt> {
    let receipt = load_context_study(root, &correction.rejected.campaign_id)?;
    anyhow::ensure!(
        correction.schema_version == 1,
        "unsupported scope correction"
    );
    anyhow::ensure!(
        receipt.plan_sha256 == correction.rejected.plan_sha256 && receipt.model == correction.model,
        "scope correction differs from its frozen proposal job"
    );
    let context = serde_json::from_value(receipt.input["threatModelRef"].clone())?;
    anyhow::ensure!(
        correction.context_ref == context,
        "scope correction context changed"
    );
    Ok(receipt)
}

fn require_original_proposal(
    workspace: &WorkspaceTarget,
    current: &ScanScopeReview,
    receipt: &ContextStudyReceipt,
) -> Result<()> {
    let reference = serde_json::from_value(receipt.input["proposalRef"].clone())?;
    let original = crate::workspace::load_scan_scope_proposal(workspace, &reference)?;
    anyhow::ensure!(
        original.reference.proposal_id == current.reference.proposal_id
            && original.record.source == current.record.source,
        "scope correction accounting belongs to a different source or proposal"
    );
    Ok(())
}
