//! One ledger fold supplies both single-study and matrix reports.
use super::*;

pub(super) fn collect_evidence(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    parents: &[String],
) -> Result<InvestigationReportEvidence> {
    let observation_run_refs = scan_finding_run_refs(workspace.root(), parents)?;
    let observation_count = store.count_finding_observations_for_scan_ids(&observation_run_refs)?;
    let findings = store.list_distinct_findings_for_scan_ids_with_identity_policy(
        &observation_run_refs,
        crate::findings::IdentityFoldPolicy::UNRESOLVED_RUN_SCOPE,
    )?;
    let review = super::super::export_workspace_findings::review_completion_for_findings(
        workspace, store, &findings,
    )?;
    let attempts = parents
        .iter()
        .map(|run| attempt_receipt(workspace.root(), run))
        .collect::<Result<Vec<_>>>()?;
    Ok(InvestigationReportEvidence {
        observation_run_refs,
        observation_count,
        finding_count: findings.len(),
        reviewed_count: review.reviewed,
        confirmed_count: review.confirmed,
        review_decision_counts: review.decisions,
        reassessment_required_count: review.reassessment_required,
        attempts,
    })
}
