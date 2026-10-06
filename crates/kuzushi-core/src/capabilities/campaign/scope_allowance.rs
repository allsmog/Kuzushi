//! Generated scope ancestry retains the investigation that paid for its proposal.
use super::*;
use crate::workspace::{ScanScopeProposalRef, ScanScopeReview, WorkspaceTarget};

pub fn load_scope_proposal_allowance(
    root: &Path,
    reference: &ScanScopeProposalRef,
) -> Result<Option<crate::allowance::AllowanceSnapshot>> {
    let workspace = WorkspaceTarget::new(root)?;
    let review = crate::workspace::load_scan_scope_proposal(&workspace, reference)?;
    let Some(generation) = &review.record.generation else {
        return Ok(None);
    };
    let (_, body) =
        crate::run_artifacts::read_run_artifact_text(root, &generation.run_id, "result.json")
            .require("Scope investigation accounting")?;
    let output: Value = serde_json::from_str(&body)?;
    validate_generation_receipt(&workspace, &review, &output)?;
    let reference: crate::allowance::AllowanceReferenceV1 =
        serde_json::from_value(output["allowanceRef"].clone())
            .context("scope generation has no authentic investigation reference")?;
    reference.validate()?;
    let snapshot = study_receipt::load_investigation_allowance(root, &reference.investigation_id)?
        .context(
            "scope generation investigation is missing; restore accounting before planning work",
        )?;
    anyhow::ensure!(
        snapshot.revision >= reference.revision,
        "scope generation allowance is newer than the ledger; restore accounting"
    );
    Ok(Some(snapshot))
}

fn validate_generation_receipt(
    workspace: &WorkspaceTarget,
    current: &ScanScopeReview,
    output: &Value,
) -> Result<()> {
    let result: ScanScopeReview = serde_json::from_value(output["data"].clone())?;
    anyhow::ensure!(
        result.reference.proposal_id == current.reference.proposal_id
            && result.record.source == current.record.source
            && result.record.generation == current.record.generation,
        "scope generation accounting belongs to a different source or proposal"
    );
    let saved = crate::workspace::load_scan_scope_proposal(workspace, &result.reference)?;
    anyhow::ensure!(
        saved == result,
        "scope generation accounting disagrees with its committed result"
    );
    Ok(())
}
