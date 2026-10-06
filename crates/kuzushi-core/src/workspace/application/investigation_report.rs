//! Rebuild study reporting from the existing plan, run receipts and ledger.
use super::*;
use crate::allowance::CampaignAllowanceReport;
use crate::capabilities::campaign::{
    load_study_plan_receipt, BatchEquivalenceKey, StudyPlanReceipt,
};
use crate::findings::{derive_batch_occurrence_report_for_controller, BatchOccurrenceReport};
use crate::run_artifacts::{load_scan_stage_data, scan_finding_run_refs, PhaseStageReceipt};
use crate::workflow_attempts::{referenced_run_content_identity, TargetContentIdentity};
use serde::Serialize;

mod scope;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationReportReceipt {
    pub schema_version: u32,
    pub campaign_id: String,
    pub plan_sha256: String,
    pub workers: usize,
    pub equivalence: BatchEquivalenceKey,
    pub scope: serde_json::Value,
    pub occurrence: BatchOccurrenceReport,
    pub observation_run_refs: Vec<String>,
    pub observation_count: usize,
    pub finding_count: usize,
    pub reviewed_count: usize,
    pub confirmed_count: usize,
    pub attempts: Vec<InvestigationAttemptReceipt>,
    pub allowance: Option<CampaignAllowanceReport>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationAttemptReceipt {
    pub run_id: String,
    pub source_identity: TargetContentIdentity,
    pub scan: Option<PhaseStageReceipt>,
}

/// Input files only locate a candidate. The authenticated queue must bind exactly
/// these runs before it can be presented as the selected investigation.
pub fn load_investigation_report_for_runs(
    workspace: &WorkspaceTarget,
    runs: &[String],
) -> Result<Option<InvestigationReportReceipt>> {
    let mut campaigns = std::collections::BTreeSet::new();
    for run in runs {
        if let Some(campaign) = report_run_campaign(workspace, run)? {
            campaigns.insert(campaign);
        }
    }
    if campaigns.is_empty() {
        return Ok(None);
    }
    anyhow::ensure!(
        campaigns.len() == 1,
        "selected Scan references multiple studies"
    );
    let receipt = load_investigation_report(workspace, campaigns.first().unwrap())?;
    let expected = runs
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let actual = receipt
        .occurrence
        .all_attempt_run_ids()
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    anyhow::ensure!(
        expected == actual,
        "selected Scan runs do not match the study's authenticated attempts"
    );
    Ok(Some(receipt))
}

fn report_run_campaign(workspace: &WorkspaceTarget, run: &str) -> Result<Option<String>> {
    match crate::SpendLimiter::read_run_campaign_report(&workspace.findings_db_path(), run)? {
        Some(campaign) => Ok(Some(campaign)),
        None => run_campaign(workspace.root(), run),
    }
}

fn run_campaign(root: &Path, run: &str) -> Result<Option<String>> {
    match crate::run_artifacts::read_run_artifact_text(root, run, "input.json") {
        crate::run_artifacts::RunArtifactRead::Missing { .. } => Ok(None),
        read => {
            let (_, value) = read.require("study run input")?;
            let value: serde_json::Value = serde_json::from_str(&value)?;
            Ok(value
                .get("batchId")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned))
        }
    }
}

/// Reporting does not accept a plan, spend money or reactivate old approval.
pub fn load_investigation_report(
    workspace: &WorkspaceTarget,
    campaign: &str,
) -> Result<InvestigationReportReceipt> {
    let plan = load_study_plan_receipt(workspace.root(), campaign)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let occurrence =
        derive_batch_occurrence_report_for_controller(workspace.root(), campaign, &store)?;
    let allowance = load_report_allowance(workspace, &plan)?;
    let parents = occurrence.all_attempt_run_ids();
    let observation_run_refs = scan_finding_run_refs(workspace.root(), &parents)?;
    let observation_count = store.count_finding_observations_for_scan_ids(&observation_run_refs)?;
    let findings = store.list_distinct_findings_for_scan_ids(&observation_run_refs)?;
    let (reviewed_count, confirmed_count) =
        super::export_workspace_findings::investigation_review_counts(&store, &findings)?;
    let attempts = parents
        .iter()
        .map(|run| attempt_receipt(workspace.root(), run))
        .collect::<Result<Vec<_>>>()?;
    Ok(InvestigationReportReceipt {
        schema_version: 1,
        campaign_id: campaign.into(),
        plan_sha256: plan.plan_sha256,
        workers: plan.workers,
        equivalence: plan.equivalence,
        scope: scope::report_scope(workspace, &plan.scan_input)?,
        occurrence,
        observation_run_refs,
        observation_count,
        finding_count: findings.len(),
        reviewed_count,
        confirmed_count,
        attempts,
        allowance,
        limitations: report_limitations(),
    })
}

fn load_report_allowance(
    workspace: &WorkspaceTarget,
    plan: &StudyPlanReceipt,
) -> Result<Option<CampaignAllowanceReport>> {
    let allowance = crate::SpendLimiter::read_campaign_allowance_report(
        &workspace.findings_db_path(),
        &plan.campaign_id,
    )?;
    validate_report_approval(plan, allowance.as_ref())?;
    if let Some(work) = allowance
        .as_ref()
        .and_then(|report| report.approval.work_plan.as_ref())
    {
        crate::capabilities::campaign::validate_campaign_report_approval(workspace.root(), work)?;
    }
    Ok(allowance)
}

fn validate_report_approval(
    plan: &StudyPlanReceipt,
    allowance: Option<&CampaignAllowanceReport>,
) -> Result<()> {
    let Some(allowance) = allowance else {
        anyhow::ensure!(
            !plan.approval_required,
            "study approval is missing; its report cannot assert approved work"
        );
        return Ok(());
    };
    let work = allowance
        .approval
        .work_plan
        .as_ref()
        .context("study approval has no work plan")?;
    anyhow::ensure!(
        work.plan_sha256 == plan.plan_sha256,
        "study plan changed after approval; report cannot bind its observations"
    );
    anyhow::ensure!(
        work.jobs.len() == plan.job_count,
        "study approved workload differs from its plan"
    );
    validate_approved_source(plan, work)
}

fn validate_approved_source(
    plan: &StudyPlanReceipt,
    work: &crate::allowance::ApprovedWorkPlanV1,
) -> Result<()> {
    anyhow::ensure!(
        work.source_identity == plan.equivalence.components.workspace_identity,
        "study approved source differs from its plan"
    );
    anyhow::ensure!(
        work.config_sha256 == plan.equivalence.components.config_sha256,
        "study approved configuration differs from its plan"
    );
    Ok(())
}

fn attempt_receipt(root: &Path, run: &str) -> Result<InvestigationAttemptReceipt> {
    Ok(InvestigationAttemptReceipt {
        run_id: run.into(),
        source_identity: referenced_run_content_identity(root, &[run.to_owned()]),
        scan: load_scan_stage_data(root, run)?,
    })
}

fn report_limitations() -> Vec<String> {
    [
        "Completed jobs describe execution, not complete repository coverage. Inventory and engine omissions are not fully recorded here.",
        "Recurrence is measured over completed trials. Failed-attempt observations remain included by their recorded run references.",
        "A missing observation never establishes a fix or carries a verdict to another source revision.",
        "Context and prompt fingerprints identify the frozen configuration. Actual provider prompts and engine-specific context omissions are not included.",
        "Allowance consumption covers the shared investigation, including context and other approved campaigns. It is not a sum of parent and child run costs.",
        "Finding rows are ledger projections with human decisions. Raw observations remain in the ledger and referenced run artifacts.",
    ].map(str::to_owned).to_vec()
}

#[cfg(test)]
pub(super) mod tests;
