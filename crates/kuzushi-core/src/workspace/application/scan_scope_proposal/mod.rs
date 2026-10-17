//! Source-bound scope revisions extend the existing strategy proposal queue.
use crate::strategy::{
    acquire_recovered_strategy_lock_cancellable, load_strategy_queue_unlocked,
    save_strategy_queue_unlocked, StrategyPhase, StrategyPreflight, StrategyProposal,
    StrategyProposalStatus, StrategyResourceRisk,
};
use crate::workspace::*;
use crate::ToolExecutionContext;
use anyhow::{Context, Result};

mod identity_coverage;
mod inventory;
mod membership;
mod persistence;
mod revision;
mod selection;
mod suggestion;
pub use selection::resolve_accepted_scan_scope_selection;
pub(crate) use suggestion::{suggest_scan_scope_proposal, validate_scan_scope_suggestion_input};

/// Describe a saved accepted boundary without checking or changing current source.
pub(crate) fn recorded_scan_scope_name(
    workspace: &WorkspaceTarget,
    reference: &ScanScopeRef,
) -> Result<String> {
    let record = persistence::load_record(workspace, &reference.proposal)?;
    anyhow::ensure!(
        record.acceptance.is_some(),
        "Recorded scope boundaries were not accepted"
    );
    record
        .draft
        .scopes
        .iter()
        .chain(record.draft.shared_scope.iter())
        .find(|scope| scope.id == reference.scope_id)
        .map(|scope| scope.name.clone())
        .context("Recorded scope is absent from its accepted proposal")
}
#[cfg(test)]
mod tests;

pub(crate) fn load_latest_scan_scope_proposal(
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<ScanScopeReview>> {
    let workspace = ctx
        .workspace
        .context("scope review requires an active target")?;
    let _guard = acquire_recovered_strategy_lock_cancellable(workspace, &|| ctx.is_cancelled())?;
    let reference = load_strategy_queue_unlocked(workspace)?
        .into_iter()
        .rev()
        .find_map(|proposal| proposal.scope_proposal_ref);
    let review = reference
        .map(|reference| persistence::load_revision(workspace, &reference))
        .transpose()?;
    anyhow::ensure!(!ctx.is_cancelled(), "scope review was canceled");
    Ok(review)
}

pub fn create_scan_scope_proposal(
    ctx: &ToolExecutionContext<'_>,
    draft: Option<ScanScopeDraft>,
) -> Result<ScanScopeReview> {
    let workspace = ctx
        .workspace
        .context("scope planning requires an active target")?;
    let (source, inventory, inventory_hash) = inventory::load_or_build(ctx)?;
    let draft = draft.unwrap_or_else(whole_repository_draft);
    let coverage = draft.evaluate(&inventory)?;
    let _guard = acquire_recovered_strategy_lock_cancellable(workspace, &|| ctx.is_cancelled())?;
    let mut queue = load_strategy_queue_unlocked(workspace)?;
    let mut proposal = StrategyProposal::new(
        StrategyPhase::ProjectModel,
        "Review scan scopes",
        "Review source membership and coverage before compiling a finite scan plan.",
    );
    proposal.id = format!("scan-scopes-{}-{}", crate::fs_atomic::now_ms(), queue.len());
    let record = revision::initial(&proposal.id, source, inventory_hash, draft);
    anyhow::ensure!(!ctx.is_cancelled(), "scope planning was canceled");
    let review = persistence::save_revision(workspace, record, coverage)?;
    bind_queue_head(&mut proposal, &review);
    queue.push(proposal);
    save_strategy_queue_unlocked(workspace, &queue)?;
    Ok(review)
}

pub fn load_scan_scope_proposal(
    workspace: &WorkspaceTarget,
    reference: &ScanScopeProposalRef,
) -> Result<ScanScopeReview> {
    load_scan_scope_proposal_cancellable(workspace, reference, &|| false)
}

pub(crate) fn load_scan_scope_proposal_cancellable(
    workspace: &WorkspaceTarget,
    reference: &ScanScopeProposalRef,
    canceled: &dyn Fn() -> bool,
) -> Result<ScanScopeReview> {
    let _guard = acquire_recovered_strategy_lock_cancellable(workspace, canceled)?;
    revision::require_committed(
        workspace,
        &load_strategy_queue_unlocked(workspace)?,
        reference,
    )?;
    let review = persistence::load_revision(workspace, reference)?;
    anyhow::ensure!(!canceled(), "scope review was canceled");
    Ok(review)
}

/// A study compiler must use this gate instead of a historical artifact read.
pub fn load_accepted_scan_scope_proposal(
    ctx: &ToolExecutionContext<'_>,
    reference: &ScanScopeProposalRef,
) -> Result<ScanScopeReview> {
    let workspace = ctx
        .workspace
        .context("accepted scope review requires an active target")?;
    let _guard = acquire_recovered_strategy_lock_cancellable(workspace, &|| ctx.is_cancelled())?;
    let queue = load_strategy_queue_unlocked(workspace)?;
    revision::require_committed(workspace, &queue, reference)?;
    let review = persistence::load_revision(workspace, reference)?;
    anyhow::ensure!(
        review.record.acceptance.is_some(),
        "scope boundaries require explicit acceptance"
    );
    inventory::ensure_current(ctx, &review.record.source)?;
    Ok(review)
}

pub fn edit_scan_scope_proposal(
    ctx: &ToolExecutionContext<'_>,
    reference: &ScanScopeProposalRef,
    edit: ScanScopeEdit,
) -> Result<ScanScopeReview> {
    update_proposal(ctx, reference, |review, inventory| {
        let (draft, coverage) = review.record.draft.edited(edit, inventory)?;
        let mut record = revision::next(review)?;
        record.draft = draft;
        record.acceptance = None;
        Ok((record, coverage))
    })
}

pub fn accept_scan_scope_proposal(
    ctx: &ToolExecutionContext<'_>,
    reference: &ScanScopeProposalRef,
    approval: ScopeCoverageApproval,
) -> Result<ScanScopeReview> {
    update_proposal(ctx, reference, |review, _| {
        review.coverage.ensure_acceptable(&approval)?;
        identity_coverage::require_bound_members(&review.identity_omissions)?;
        let mut record = revision::next(review)?;
        record.acceptance = Some(approval);
        Ok((record, review.coverage.clone()))
    })
}

fn update_proposal(
    ctx: &ToolExecutionContext<'_>,
    reference: &ScanScopeProposalRef,
    update: impl FnOnce(
        &ScanScopeReview,
        &RepositoryInventory,
    ) -> Result<(ScanScopeRevision, ScanScopeCoverage)>,
) -> Result<ScanScopeReview> {
    let workspace = ctx
        .workspace
        .context("scope review requires an active target")?;
    let _guard = acquire_recovered_strategy_lock_cancellable(workspace, &|| ctx.is_cancelled())?;
    let mut queue = load_strategy_queue_unlocked(workspace)?;
    let proposal = revision::current_head(&mut queue, reference)?;
    let review = persistence::load_revision(workspace, reference)?;
    inventory::ensure_current(ctx, &review.record.source)?;
    let inventory = persistence::load_inventory(workspace, &review.record.inventory_hash)?;
    let (record, coverage) = update(&review, &inventory)?;
    inventory::ensure_current(ctx, &record.source)?;
    anyhow::ensure!(!ctx.is_cancelled(), "scope review was canceled");
    let next = persistence::save_revision(workspace, record, coverage)?;
    bind_queue_head(proposal, &next);
    save_strategy_queue_unlocked(workspace, &queue)?;
    Ok(next)
}

fn bind_queue_head(proposal: &mut StrategyProposal, review: &ScanScopeReview) {
    proposal.tool = None;
    proposal.next_input = None;
    proposal.scope_proposal_ref = Some(review.reference.clone());
    proposal.status = if review.record.acceptance.is_some() {
        StrategyProposalStatus::Done
    } else {
        StrategyProposalStatus::Proposed
    };
    proposal.updated_at_ms = crate::fs_atomic::now_ms();
    proposal.preflight = StrategyPreflight::blocked(vec![
        "Review scope boundaries separately; this proposal cannot launch scan jobs.".into(),
    ]);
    proposal.resource_risk = StrategyResourceRisk::Unknown;
    proposal.expected_cost_usd = None;
}

pub fn scan_scope_proposal_files(
    workspace: &WorkspaceTarget,
    reference: &ScanScopeProposalRef,
    filter: ScopeFileFilter,
    offset: usize,
    size: usize,
) -> Result<ScopeFilePage> {
    scan_scope_proposal_files_cancellable(workspace, reference, filter, offset, size, &|| false)
}

pub(crate) fn scan_scope_proposal_files_cancellable(
    workspace: &WorkspaceTarget,
    reference: &ScanScopeProposalRef,
    filter: ScopeFileFilter,
    offset: usize,
    size: usize,
    canceled: &dyn Fn() -> bool,
) -> Result<ScopeFilePage> {
    let review = load_scan_scope_proposal_cancellable(workspace, reference, canceled)?;
    let inventory = persistence::load_inventory(workspace, &review.record.inventory_hash)?;
    review
        .record
        .draft
        .file_page(&inventory, filter, offset, size)
}

fn whole_repository_draft() -> ScanScopeDraft {
    ScanScopeDraft {
        schema_version: 1,
        scopes: vec![ProposedScanScope {
            id: "repository".into(),
            name: "Whole repository".into(),
            paths: vec![".".into()],
            rationale:
                "Keep the repository together until the operator chooses component boundaries."
                    .into(),
            shared_dependencies: Vec::new(),
            open_questions: Vec::new(),
        }],
        shared_scope: None,
        shared_discovery: false,
        exclusions: Vec::new(),
    }
}
