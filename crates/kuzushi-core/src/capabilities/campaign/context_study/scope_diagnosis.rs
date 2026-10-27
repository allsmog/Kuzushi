use super::*;
use crate::workspace::{
    RejectedScopeCandidate, RejectedScopeRef, ScanScopeCorrection, ScanScopeDraft, ScanScopeReview,
};
use crate::WorkspaceTarget;

const LEAF: &str = "rejected-scope-output.json";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectedScopeDraft {
    pub reference: RejectedScopeRef,
    pub candidate: String,
    pub complete: bool,
    pub original_bytes: usize,
    pub reason: String,
}

impl ContextStudyReceipt {
    pub fn corrected_scopes(&self, root: &Path) -> Result<Option<ScanScopeReview>> {
        anyhow::ensure!(
            self.generation_tool == generation::SCOPE_TOOL,
            "this job does not propose scopes"
        );
        let original: crate::workspace::ScanScopeProposalRef =
            serde_json::from_value(self.input["proposalRef"].clone())?;
        let workspace = WorkspaceTarget::new(root)?;
        let reference = crate::strategy::load_strategy_queue(&workspace)?
            .into_iter()
            .find(|proposal| proposal.id == original.proposal_id)
            .and_then(|proposal| proposal.scope_proposal_ref);
        let Some(reference) = reference else {
            return Ok(None);
        };
        let review = crate::workspace::load_scan_scope_proposal(&workspace, &reference)?;
        let Some(correction) = &review.record.correction else {
            return Ok(None);
        };
        if correction.rejected.campaign_id != self.campaign_id
            || correction.rejected.plan_sha256 != self.plan_sha256
        {
            return Ok(None);
        }
        let output = self
            .rejected_scope_draft(root)?
            .context("corrected draft's rejected output is unavailable")?;
        anyhow::ensure!(
            correction.rejected == output.reference,
            "corrected scope history differs from its rejected output"
        );
        Ok(Some(review))
    }

    pub fn rejected_scope_draft(&self, root: &Path) -> Result<Option<RejectedScopeDraft>> {
        anyhow::ensure!(
            self.generation_tool == generation::SCOPE_TOOL,
            "this job does not propose scopes"
        );
        let Some(run) = self.diagnostic_run(root)? else {
            return Ok(None);
        };
        let (_, text) =
            crate::run_artifacts::read_run_artifact_text_bounded(root, &run, LEAF, 128 * 1024)?;
        let artifact = crate::run_artifacts::load_run_artifact_object_reference(root, &run, LEAF)?;
        anyhow::ensure!(
            artifact.size_bytes == text.len() as u64
                && artifact.hash
                    == crate::content_store::object_hash(artifact.kind, text.as_bytes()),
            "rejected scope output changed since publication"
        );
        let candidate: RejectedScopeCandidate = serde_json::from_str(&text)?;
        candidate.validate()?;
        require_failed_scope(root, self, &run)?;
        Ok(Some(RejectedScopeDraft {
            reference: RejectedScopeRef {
                schema_version: 1,
                campaign_id: self.campaign_id.clone(),
                plan_sha256: self.plan_sha256.clone(),
                run_id: run,
                artifact_hash: artifact.hash.to_string(),
            },
            candidate: candidate.candidate,
            complete: candidate.complete,
            original_bytes: candidate.original_bytes,
            reason: candidate.reason,
        }))
    }

    pub(super) fn scope_diagnostic(&self, root: &Path) -> Result<Option<RejectedContextOutput>> {
        let Some(output) = self.rejected_scope_draft(root)? else {
            return Ok(None);
        };
        let text = format!("Rejected scope proposal. {} of {} model-text bytes retained; complete: {}.\nReason: {}\n\n{}",
            output.candidate.len(), output.original_bytes, output.complete, output.reason, output.candidate);
        Ok(Some(RejectedContextOutput {
            path: root
                .join(".kuzushi/v3/runs")
                .join(&output.reference.run_id)
                .join(LEAF),
            run_id: output.reference.run_id,
            source_identity: self.source_identity.clone(),
            model: self.model.clone(),
            text,
        }))
    }
}

fn require_failed_scope(root: &Path, receipt: &ContextStudyReceipt, run: &str) -> Result<()> {
    let snapshot = super::super::snapshot::load_campaign_snapshot(root, &receipt.campaign_id)?;
    anyhow::ensure!(
        snapshot.jobs.iter().any(|job| job.job_id == JOB
            && job.state == "failed"
            && job.run_id.as_deref() == Some(run)),
        "scope diagnostic does not belong to a failed job"
    );
    Ok(())
}

pub(crate) fn recover_scope_draft(
    ctx: &ToolExecutionContext<'_>,
    reference: &RejectedScopeRef,
    draft: ScanScopeDraft,
) -> Result<ScanScopeReview> {
    anyhow::ensure!(
        reference.schema_version == 1,
        "unsupported rejected scope reference"
    );
    let root = ctx
        .workspace
        .context("scope correction requires a workspace")?
        .root();
    let receipt = load_context_study(root, &reference.campaign_id)?;
    anyhow::ensure!(
        receipt.plan_sha256 == reference.plan_sha256,
        "scope recovery plan changed"
    );
    let output = receipt
        .rejected_scope_draft(root)?
        .context("no rejected scope output was retained")?;
    anyhow::ensure!(
        output.reference == *reference,
        "rejected scope output differs from the reviewed diagnostic"
    );
    anyhow::ensure!(
        output.complete,
        "partial scope output cannot be recovered; create a manual scope draft instead"
    );
    let original = serde_json::from_value(receipt.input["proposalRef"].clone())?;
    let correction = correction_receipt(receipt, reference, &draft)?;
    crate::workspace::correct_rejected_scan_scope(ctx, &original, draft, correction)
}

fn correction_receipt(
    receipt: ContextStudyReceipt,
    reference: &RejectedScopeRef,
    draft: &ScanScopeDraft,
) -> Result<ScanScopeCorrection> {
    Ok(ScanScopeCorrection {
        schema_version: 1,
        rejected: reference.clone(),
        model: receipt.model,
        context_ref: serde_json::from_value(receipt.input["threatModelRef"].clone())?,
        corrected_draft_sha256: crate::options::prompt_content_sha256(&serde_json::to_string(
            draft,
        )?),
    })
}
