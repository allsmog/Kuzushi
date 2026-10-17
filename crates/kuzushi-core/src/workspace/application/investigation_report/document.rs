//! Report shapes preserve context boundaries and the existing single-study format.
use super::*;
use crate::capabilities::campaign::FrozenContextCase;
use crate::findings::ContextMatrixOccurrenceReport;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum InvestigationReportDocument {
    Study(InvestigationReportReceipt),
    ContextMatrix(ContextMatrixInvestigationReceipt),
    ScopeStudy(ScopeStudyInvestigationReceipt),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeStudyInvestigationReceipt {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub investigation_brief: Option<crate::capabilities::campaign::BriefRevision>,
    pub schema_version: u32,
    pub kind: String,
    pub campaign_id: String,
    pub plan_sha256: String,
    pub workers: usize,
    pub cases: Vec<InvestigationContextCase>,
    pub scope: serde_json::Value,
    pub unplanned_scope_ids: Vec<String>,
    pub occurrence: crate::findings::ScopeStudyOccurrenceReport,
    #[serde(flatten)]
    pub evidence: InvestigationReportEvidence,
    pub allowance: Option<CampaignAllowanceReport>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextMatrixInvestigationReceipt {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub investigation_brief: Option<crate::capabilities::campaign::BriefRevision>,
    pub schema_version: u32,
    pub kind: String,
    pub campaign_id: String,
    pub plan_sha256: String,
    pub workers: usize,
    pub baseline_case_id: String,
    pub cases: Vec<InvestigationContextCase>,
    pub scope: serde_json::Value,
    pub occurrence: ContextMatrixOccurrenceReport,
    #[serde(flatten)]
    pub evidence: InvestigationReportEvidence,
    pub allowance: Option<CampaignAllowanceReport>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationContextCase {
    pub id: String,
    pub label: String,
    pub passes: usize,
    pub equivalence: BatchEquivalenceKey,
}

impl From<&FrozenContextCase> for InvestigationContextCase {
    fn from(case: &FrozenContextCase) -> Self {
        Self {
            id: case.id.clone(),
            label: case.label.clone(),
            passes: case.passes,
            equivalence: case.equivalence.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationReportEvidence {
    pub observation_run_refs: Vec<String>,
    pub observation_count: usize,
    pub finding_count: usize,
    pub reviewed_count: usize,
    pub confirmed_count: usize,
    pub review_decision_counts: crate::findings::ReviewDecisionCounts,
    pub reassessment_required_count: usize,
    pub attempts: Vec<InvestigationAttemptReceipt>,
}

/// These totals count work and ledger rows, never recurrence across contexts.
pub struct InvestigationReportSummary<'a> {
    pub investigation_brief: Option<&'a crate::capabilities::campaign::BriefRevision>,
    pub campaign_id: &'a str,
    pub plan_sha256: &'a str,
    pub workers: usize,
    pub observation_run_refs: &'a [String],
    pub observation_count: usize,
    pub finding_count: usize,
    pub reviewed_count: usize,
    pub confirmed_count: usize,
    pub review_decision_counts: crate::findings::ReviewDecisionCounts,
    pub reassessment_required_count: usize,
    pub attempts: &'a [InvestigationAttemptReceipt],
    pub allowance: Option<&'a CampaignAllowanceReport>,
    pub limitations: &'a [String],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InvestigationWorkCounts {
    pub planned: usize,
    pub completed: usize,
    pub failed: usize,
    pub pending: usize,
}

impl InvestigationReportDocument {
    pub(crate) fn phase_result_run_ids(&self) -> Result<Vec<String>> {
        let work = self.work_counts();
        if work.completed != work.planned || work.planned == 0 {
            return Ok(self
                .summary()
                .attempts
                .iter()
                .map(|attempt| attempt.run_id.clone())
                .collect());
        }
        let mut runs = std::collections::BTreeSet::new();
        for occurrence in self.phase_occurrences() {
            runs.extend(occurrence.phase_result_run_ids()?);
        }
        Ok(runs.into_iter().collect())
    }

    fn phase_occurrences(&self) -> Vec<&crate::findings::BatchOccurrenceReport> {
        match self {
            Self::Study(receipt) => vec![&receipt.occurrence],
            Self::ContextMatrix(receipt) => receipt
                .occurrence
                .cases
                .iter()
                .map(|case| &case.occurrence)
                .collect(),
            Self::ScopeStudy(receipt) => receipt
                .occurrence
                .cases
                .iter()
                .map(|case| &case.occurrence)
                .collect(),
        }
    }

    pub fn frozen_source_identity(&self) -> Result<&str> {
        let components = match self {
            Self::Study(receipt) => &receipt.equivalence.components,
            Self::ContextMatrix(receipt) => {
                &receipt
                    .cases
                    .iter()
                    .find(|case| case.id == receipt.baseline_case_id)
                    .context("Matrix baseline is missing")?
                    .equivalence
                    .components
            }
            Self::ScopeStudy(receipt) => {
                &receipt
                    .cases
                    .first()
                    .context("Scope study has no cases")?
                    .equivalence
                    .components
            }
        };
        Ok(&components.workspace_identity)
    }

    pub fn summary(&self) -> InvestigationReportSummary<'_> {
        match self {
            Self::Study(receipt) => study_summary(receipt),
            Self::ContextMatrix(receipt) => matrix_summary(receipt),
            Self::ScopeStudy(receipt) => scope_study_summary(receipt),
        }
    }

    pub fn work_counts(&self) -> InvestigationWorkCounts {
        match self {
            Self::Study(receipt) => work_counts(&receipt.occurrence),
            Self::ScopeStudy(receipt) => receipt.occurrence.cases.iter().fold(
                InvestigationWorkCounts::default(),
                |mut total, case| {
                    let work = work_counts(&case.occurrence);
                    total.planned += work.planned;
                    total.completed += work.completed;
                    total.failed += work.failed;
                    total.pending += work.pending;
                    total
                },
            ),
            Self::ContextMatrix(receipt) => receipt.occurrence.cases.iter().fold(
                InvestigationWorkCounts::default(),
                |mut total, case| {
                    let work = work_counts(&case.occurrence);
                    total.planned += work.planned;
                    total.completed += work.completed;
                    total.failed += work.failed;
                    total.pending += work.pending;
                    total
                },
            ),
        }
    }
}

fn scope_study_summary(receipt: &ScopeStudyInvestigationReceipt) -> InvestigationReportSummary<'_> {
    let evidence = &receipt.evidence;
    InvestigationReportSummary {
        investigation_brief: receipt.investigation_brief.as_ref(),
        campaign_id: &receipt.campaign_id,
        plan_sha256: &receipt.plan_sha256,
        workers: receipt.workers,
        observation_run_refs: &evidence.observation_run_refs,
        observation_count: evidence.observation_count,
        finding_count: evidence.finding_count,
        reviewed_count: evidence.reviewed_count,
        confirmed_count: evidence.confirmed_count,
        review_decision_counts: evidence.review_decision_counts,
        reassessment_required_count: evidence.reassessment_required_count,
        attempts: &evidence.attempts,
        allowance: receipt.allowance.as_ref(),
        limitations: &receipt.limitations,
    }
}

fn work_counts(report: &BatchOccurrenceReport) -> InvestigationWorkCounts {
    InvestigationWorkCounts {
        planned: report.planned,
        completed: report.completed,
        failed: report.failed,
        pending: report.pending,
    }
}

fn study_summary(receipt: &InvestigationReportReceipt) -> InvestigationReportSummary<'_> {
    InvestigationReportSummary {
        investigation_brief: receipt.investigation_brief.as_ref(),
        campaign_id: &receipt.campaign_id,
        plan_sha256: &receipt.plan_sha256,
        workers: receipt.workers,
        observation_run_refs: &receipt.observation_run_refs,
        observation_count: receipt.observation_count,
        finding_count: receipt.finding_count,
        reviewed_count: receipt.reviewed_count,
        confirmed_count: receipt.confirmed_count,
        review_decision_counts: receipt.review_decision_counts,
        reassessment_required_count: receipt.reassessment_required_count,
        attempts: &receipt.attempts,
        allowance: receipt.allowance.as_ref(),
        limitations: &receipt.limitations,
    }
}

fn matrix_summary(receipt: &ContextMatrixInvestigationReceipt) -> InvestigationReportSummary<'_> {
    let evidence = &receipt.evidence;
    InvestigationReportSummary {
        investigation_brief: receipt.investigation_brief.as_ref(),
        campaign_id: &receipt.campaign_id,
        plan_sha256: &receipt.plan_sha256,
        workers: receipt.workers,
        observation_run_refs: &evidence.observation_run_refs,
        observation_count: evidence.observation_count,
        finding_count: evidence.finding_count,
        reviewed_count: evidence.reviewed_count,
        confirmed_count: evidence.confirmed_count,
        review_decision_counts: evidence.review_decision_counts,
        reassessment_required_count: evidence.reassessment_required_count,
        attempts: &evidence.attempts,
        allowance: receipt.allowance.as_ref(),
        limitations: &receipt.limitations,
    }
}
