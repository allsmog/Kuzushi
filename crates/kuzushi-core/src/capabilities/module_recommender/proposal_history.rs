//! Recommendation refresh adds drafts without rewriting human review history.
use crate::strategy::{StrategyProposal, StrategyProposalStatus};
use anyhow::Result;

pub(super) fn retain_draft(
    proposals: &mut Vec<StrategyProposal>,
    mut next: StrategyProposal,
) -> Result<String> {
    anyhow::ensure!(
        next.status == StrategyProposalStatus::Proposed,
        "Regenerated recommendations must be unapproved drafts"
    );
    if let Some(existing) = proposals
        .iter()
        .find(|existing| same_generation(existing, &next))
    {
        return Ok(existing.id.clone());
    }
    if proposals.iter().any(|existing| existing.id == next.id) {
        next.id = collision_id(&next.id, proposals)?;
    }
    let id = next.id.clone();
    proposals.push(next);
    Ok(id)
}

fn same_generation(existing: &StrategyProposal, next: &StrategyProposal) -> bool {
    let Some(run) = next.source_run_id.as_deref() else {
        return false;
    };
    existing.status == StrategyProposalStatus::Proposed
        && existing.source_run_id.as_deref() == Some(run)
        && recommendation_payload(existing) == recommendation_payload(next)
}

fn recommendation_payload(proposal: &StrategyProposal) -> serde_json::Value {
    serde_json::json!({"phase":proposal.phase,"base":proposal.base_strategy,
        "recommended":proposal.recommended_strategy,"corrected":proposal.corrected_strategy,
        "corrections":proposal.applied_corrections,"rationale":proposal.rationale,
        "tool":proposal.tool,"input":proposal.next_input,"scope":proposal.scope_proposal_ref,
        "estimate":proposal.expected_cost_usd,"runtime":proposal.expected_runtime,
        "yield":proposal.yield_score,"rounds":proposal.estimated_rounds,
        "preflight":proposal.preflight,"risk":proposal.resource_risk})
}

fn collision_id(base: &str, proposals: &[StrategyProposal]) -> Result<String> {
    let id = format!("{base}-draft-{}", uuid::Uuid::new_v4().simple());
    anyhow::ensure!(
        !proposals.iter().any(|existing| existing.id == id),
        "Recommendation draft identity collision; prior proposals were retained"
    );
    Ok(id)
}

#[cfg(test)]
mod tests;
