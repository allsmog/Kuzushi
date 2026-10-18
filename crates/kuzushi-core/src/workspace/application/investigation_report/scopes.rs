//! Scoped reports keep eligible repetition counts inside each boundary.
use super::*;
use crate::capabilities::campaign::{load_scope_study_receipt, ScopeStudyReceipt};

pub(super) fn load_scope_report(
    workspace: &WorkspaceTarget,
    campaign: &str,
) -> Result<ScopeStudyInvestigationReceipt> {
    let plan = load_scope_study_receipt(workspace.root(), campaign)?;
    let allowance = scope_allowance(workspace, &plan)?;
    let store = FindingStore::open_read_only(workspace.findings_db_path())?;
    let occurrence =
        crate::findings::derive_scope_study_occurrence_report(workspace.root(), campaign, &store)?;
    anyhow::ensure!(
        occurrence.plan_sha256 == plan.plan_sha256,
        "Scope study changed during report loading"
    );
    let parents = occurrence
        .cases
        .iter()
        .flat_map(|case| case.occurrence.all_attempt_run_ids())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let evidence = collect_evidence(workspace, &store, &parents)?;
    let scopes = scope_values(workspace, &plan)?;
    let brief = crate::capabilities::campaign::load_plan_brief(workspace.root(), campaign)?;
    Ok(report_receipt(
        campaign, plan, occurrence, evidence, allowance, scopes, brief,
    ))
}

fn scope_values(
    workspace: &WorkspaceTarget,
    plan: &ScopeStudyReceipt,
) -> Result<serde_json::Value> {
    let scopes = plan
        .scope_study
        .cases
        .iter()
        .map(|case| {
            Ok((
                case.id.clone(),
                scope::report_scope(workspace, &case.base_input)?,
            ))
        })
        .collect::<Result<serde_json::Map<String, serde_json::Value>>>()?;
    Ok(serde_json::Value::Object(scopes))
}

fn report_receipt(
    campaign: &str,
    plan: ScopeStudyReceipt,
    occurrence: crate::findings::ScopeStudyOccurrenceReport,
    evidence: InvestigationReportEvidence,
    allowance: CampaignAllowanceReport,
    scopes: serde_json::Value,
    investigation_brief: Option<crate::capabilities::campaign::BriefRevision>,
) -> ScopeStudyInvestigationReceipt {
    ScopeStudyInvestigationReceipt {
        investigation_brief,
        schema_version: 1,
        kind: crate::capabilities::campaign::SCOPE_STUDY_KIND.into(),
        campaign_id: campaign.into(),
        plan_sha256: plan.plan_sha256,
        workers: plan.workers,
        scope_proposal_ref: plan.scope_study.proposal_ref,
        inherited_threat_model_ref: plan.scope_study.inherited_threat_model_ref,
        context_selections: plan.scope_study.selections,
        cases: plan
            .scope_study
            .cases
            .iter()
            .map(InvestigationContextCase::from)
            .collect(),
        scope: scopes,
        unplanned_scope_ids: plan.scope_study.unplanned_scope_ids,
        occurrence,
        evidence,
        allowance: Some(allowance),
        limitations: report_limitations(),
    }
}

fn scope_allowance(
    workspace: &WorkspaceTarget,
    plan: &ScopeStudyReceipt,
) -> Result<CampaignAllowanceReport> {
    let report = crate::SpendLimiter::read_campaign_allowance_report(
        &workspace.findings_db_path(),
        &plan.campaign_id,
    )?
    .context("Scope study approval is missing")?;
    let work = report
        .approval
        .work_plan
        .as_ref()
        .context("Scope study approval has no finite work plan")?;
    anyhow::ensure!(
        work.plan_sha256 == plan.plan_sha256 && work.jobs.len() == plan.job_count,
        "Scope study approval differs from its frozen work"
    );
    let source = &plan.scope_study.first()?.equivalence.components;
    anyhow::ensure!(
        work.source_identity == source.workspace_identity
            && work.config_sha256 == source.config_sha256,
        "Scope study approval differs from its recorded source or configuration"
    );
    crate::capabilities::campaign::validate_campaign_report_approval(workspace.root(), work)?;
    Ok(report)
}
