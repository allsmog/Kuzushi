use crate::findings::{
    Finding, ReviewDecision, ReviewDecisionConflict, ReviewDecisionRecord, TriageVerdict,
};

#[derive(Debug, Clone, PartialEq)]
pub struct WorkspaceFindingReviewContext {
    pub(super) decision: ReviewDecision,
    pub(super) triage_verdict: Option<TriageVerdict>,
    pub(super) decided_at: Option<String>,
    pub(super) read_watermark: Option<u64>,
    source: WorkspaceFindingReviewSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceFindingReviewSource {
    SelectedFinding,
    DurableIdentity,
    Unknown,
}

impl WorkspaceFindingReviewContext {
    pub fn from_decision(decision: ReviewDecision, triage_verdict: Option<TriageVerdict>) -> Self {
        Self {
            decision,
            triage_verdict,
            decided_at: None,
            read_watermark: None,
            source: WorkspaceFindingReviewSource::Unknown,
        }
    }

    pub(super) fn from_record(record: &ReviewDecisionRecord) -> Self {
        Self {
            decision: record.decision.clone(),
            triage_verdict: record.triage_verdict,
            decided_at: Some(record.created_at.clone()),
            read_watermark: record
                .provenance
                .as_ref()
                .and_then(|value| value.read_watermark),
            source: WorkspaceFindingReviewSource::Unknown,
        }
    }

    pub(super) fn from_record_for_finding(
        record: &ReviewDecisionRecord,
        finding: &Finding,
    ) -> Self {
        let mut context = Self::from_record(record);
        context.source = review_source_for_finding(record.finding_id, finding);
        context
    }

    pub fn from_carried_decision(
        decision: ReviewDecision,
        triage_verdict: Option<TriageVerdict>,
        carried_from_durable_identity: bool,
    ) -> Self {
        Self {
            decision,
            triage_verdict,
            decided_at: None,
            read_watermark: None,
            source: carried_decision_source(carried_from_durable_identity),
        }
    }

    pub(super) fn from_finding(finding: &Finding) -> Option<Self> {
        finding.triage.as_ref().map(|triage| Self {
            decision: ReviewDecision::from_triage(triage, finding.triaged_by),
            triage_verdict: Some(triage.verdict),
            decided_at: None,
            read_watermark: None,
            source: WorkspaceFindingReviewSource::SelectedFinding,
        })
    }

    pub fn is_terminal(&self) -> bool {
        self.decision.verdict.is_terminal()
    }

    pub fn is_terminal_for_finding(&self, finding: &Finding) -> bool {
        self.is_terminal() && self.decision_conflict_label(finding).is_none()
    }

    pub fn decision_conflict_label(&self, finding: &Finding) -> Option<&'static str> {
        ReviewDecisionConflict::classify(
            finding,
            self.decision.verdict,
            self.source == WorkspaceFindingReviewSource::DurableIdentity,
        )
        .map(ReviewDecisionConflict::export_token)
    }
}

fn carried_decision_source(carried: bool) -> WorkspaceFindingReviewSource {
    if carried {
        WorkspaceFindingReviewSource::DurableIdentity
    } else {
        WorkspaceFindingReviewSource::SelectedFinding
    }
}

fn review_source_for_finding(
    review_finding_id: i64,
    finding: &Finding,
) -> WorkspaceFindingReviewSource {
    if finding.id == Some(review_finding_id) {
        WorkspaceFindingReviewSource::SelectedFinding
    } else {
        WorkspaceFindingReviewSource::DurableIdentity
    }
}
