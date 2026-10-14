//! Authenticate frozen cases before rebuilding a read-only report.
use super::*;
use crate::capabilities::campaign::{load_context_matrix_receipt, ContextMatrixReceipt};
use crate::findings::derive_context_matrix_occurrence_report;
use serde_json::Value;

pub(super) fn load_matrix_report(
    workspace: &WorkspaceTarget,
    campaign: &str,
) -> Result<ContextMatrixInvestigationReceipt> {
    let plan = load_context_matrix_receipt(workspace.root(), campaign)?;
    let allowance = matrix_allowance(workspace, &plan)?;
    let store = FindingStore::open_read_only(workspace.findings_db_path())?;
    let occurrence = derive_context_matrix_occurrence_report(workspace.root(), campaign, &store)?;
    anyhow::ensure!(
        occurrence.plan_sha256 == plan.plan_sha256,
        "Matrix changed during report loading"
    );
    let parents = matrix_attempt_runs(&occurrence);
    let evidence = collect_evidence(workspace, &store, &parents)?;
    let baseline = plan.matrix.baseline()?;
    Ok(ContextMatrixInvestigationReceipt {
        investigation_brief: crate::capabilities::campaign::load_plan_brief(
            workspace.root(),
            campaign,
        )?,
        schema_version: 1,
        kind: crate::capabilities::campaign::CONTEXT_MATRIX_KIND.into(),
        campaign_id: campaign.into(),
        plan_sha256: plan.plan_sha256,
        workers: plan.workers,
        baseline_case_id: plan.matrix.baseline_case_id.clone(),
        cases: plan
            .matrix
            .cases
            .iter()
            .map(InvestigationContextCase::from)
            .collect(),
        scope: matrix_scope(workspace, &plan.matrix.cases, &baseline.base_input)?,
        occurrence,
        evidence,
        allowance: Some(allowance),
        limitations: report_limitations(),
    })
}

fn matrix_scope(
    workspace: &WorkspaceTarget,
    cases: &[crate::capabilities::campaign::FrozenContextCase],
    baseline: &Value,
) -> Result<Value> {
    let mut scope = scope::report_scope(workspace, baseline)?;
    scope["caseContextGuidance"] = Value::Object(
        cases
            .iter()
            .map(|case| {
                (
                    case.id.clone(),
                    scope::recorded_context_guidance(workspace, &case.base_input),
                )
            })
            .collect(),
    );
    Ok(scope)
}

fn matrix_attempt_runs(report: &crate::findings::ContextMatrixOccurrenceReport) -> Vec<String> {
    report
        .cases
        .iter()
        .flat_map(|case| case.occurrence.all_attempt_run_ids())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn matrix_allowance(
    workspace: &WorkspaceTarget,
    plan: &ContextMatrixReceipt,
) -> Result<CampaignAllowanceReport> {
    let report = crate::SpendLimiter::read_campaign_allowance_report(
        &workspace.findings_db_path(),
        &plan.campaign_id,
    )?
    .context("matrix approval is missing; its report cannot assert approved work")?;
    let work = report
        .approval
        .work_plan
        .as_ref()
        .context("matrix approval has no work plan")?;
    anyhow::ensure!(
        work.plan_sha256 == plan.plan_sha256 && work.jobs.len() == plan.job_count,
        "matrix approved plan or workload differs from its frozen receipt"
    );
    let source = &plan.matrix.baseline()?.equivalence.components;
    anyhow::ensure!(
        work.source_identity == source.workspace_identity
            && work.config_sha256 == source.config_sha256,
        "matrix approved source or configuration differs from its receipt"
    );
    crate::capabilities::campaign::validate_campaign_report_approval(workspace.root(), work)?;
    Ok(report)
}
