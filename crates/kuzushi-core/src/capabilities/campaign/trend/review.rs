//! Effective review counts over current canonical projections, independent of UI filters.
use super::{metrics_from_verdicts, TrendMetrics, WorkspaceCampaignSpend};
use crate::findings::{
    EffectiveReviewStateIndex, Finding, ReviewDecisionRecord, ReviewDecisionSubject,
};

/// Subjects must be the current canonical projection, not repeated observations.
/// Exact-row decisions remain local; recorded identity decisions may be carried.
pub fn trend_metrics_for_subjects(
    subjects: &[ReviewDecisionSubject],
    records: &[ReviewDecisionRecord],
    spend: WorkspaceCampaignSpend,
) -> TrendMetrics {
    let index = EffectiveReviewStateIndex::from_findings_and_decisions(&[], records);
    metrics_from_verdicts(
        subjects
            .iter()
            .filter_map(|subject| index.verdict_for_subject(subject)),
        spend,
    )
}

/// Count recorded decisions over canonical findings. Embedded legacy triage
/// without a review record does not manufacture a decision-ledger count.
pub fn trend_metrics_for_findings(
    findings: &[Finding],
    records: &[ReviewDecisionRecord],
    spend: WorkspaceCampaignSpend,
) -> TrendMetrics {
    let index = EffectiveReviewStateIndex::from_findings_and_decisions(&[], records);
    metrics_from_verdicts(
        findings
            .iter()
            .filter_map(|finding| index.verdict_for_subject(&ReviewDecisionSubject::from(finding))),
        spend,
    )
}

#[cfg(test)]
mod tests;
