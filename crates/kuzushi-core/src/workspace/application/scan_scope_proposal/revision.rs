use super::*;

pub(super) fn initial(
    proposal_id: &str,
    source: ScanScopeSource,
    inventory_hash: String,
    draft: ScanScopeDraft,
) -> ScanScopeRevision {
    ScanScopeRevision {
        schema_version: 1,
        proposal_id: proposal_id.into(),
        revision: 1,
        previous: None,
        source,
        inventory_hash,
        draft,
        acceptance: None,
        generation: None,
        correction: None,
    }
}

pub(super) fn next(review: &ScanScopeReview) -> Result<ScanScopeRevision> {
    let mut record = review.record.clone();
    record.revision = record
        .revision
        .checked_add(1)
        .context("scope revision limit reached")?;
    record.previous = Some(review.reference.clone());
    Ok(record)
}

pub(super) fn current_head<'a>(
    queue: &'a mut [StrategyProposal],
    reference: &ScanScopeProposalRef,
) -> Result<&'a mut StrategyProposal> {
    let proposal = queue
        .iter_mut()
        .find(|entry| entry.id == reference.proposal_id)
        .context("scope proposal is not in the proposal queue")?;
    let current = proposal
        .scope_proposal_ref
        .as_ref()
        .context("proposal is not a scan scope draft")?;
    anyhow::ensure!(
        current == reference,
        "scope draft changed; reload the current revision before editing or accepting"
    );
    Ok(proposal)
}

pub(super) fn require_committed(
    workspace: &WorkspaceTarget,
    queue: &[StrategyProposal],
    reference: &ScanScopeProposalRef,
) -> Result<()> {
    let proposal = queue
        .iter()
        .find(|entry| entry.id == reference.proposal_id)
        .context("scope proposal is not in the proposal queue")?;
    let mut current = proposal
        .scope_proposal_ref
        .clone()
        .context("proposal is not a scan scope draft")?;
    for _ in 0..4096 {
        if current == *reference {
            return Ok(());
        }
        anyhow::ensure!(
            current.revision > reference.revision,
            "scope revision is not committed in the proposal history"
        );
        current = persistence::load_record(workspace, &current)?
            .previous
            .context("scope revision is not committed in the proposal history")?;
    }
    anyhow::bail!("scope history exceeds its 4096-revision read limit")
}
