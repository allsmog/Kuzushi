use super::review_conflicts::effective_review_decision_conflict_label;
use kuzushi_core::findings::{
    finding_lifecycle_status, ReviewDecision, ReviewDecisionRecord, ReviewDecisionVerdict,
};
use kuzushi_core::workspace::WorkspaceFindingReviewContext;
use kuzushi_core::Finding;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EffectiveReviewDecision {
    decision: ReviewDecision,
    source: EffectiveReviewDecisionSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectiveReviewDecisionSource {
    SelectedFinding,
    DurableIdentity,
}

impl EffectiveReviewDecision {
    fn from_finding(finding: &Finding) -> Option<Self> {
        finding.triage.as_ref().map(|triage| Self {
            decision: ReviewDecision::from_triage(triage, finding.triaged_by),
            source: EffectiveReviewDecisionSource::SelectedFinding,
        })
    }

    fn from_indexed(indexed: &IndexedReviewDecision, finding: &Finding) -> Self {
        Self {
            decision: indexed.decision.clone(),
            source: indexed_decision_source(finding, indexed.finding_id),
        }
    }

    pub(crate) fn verdict(&self) -> ReviewDecisionVerdict {
        self.decision.verdict
    }

    pub(crate) fn review_decision(&self) -> &ReviewDecision {
        &self.decision
    }

    pub(crate) fn carried_from_durable_identity(&self) -> bool {
        self.source == EffectiveReviewDecisionSource::DurableIdentity
    }

    pub(crate) fn decision_label(&self) -> String {
        self.decision.verdict.as_str().to_string()
    }

    pub(crate) fn complete(&self) -> bool {
        self.decision.verdict.is_terminal()
    }

    pub(crate) fn confidence_label(&self) -> String {
        format!("{:.0}%", self.decision.confidence.clamp(0.0, 1.0) * 100.0)
    }

    pub(crate) fn author_label(&self) -> String {
        self.decision.author.as_str().to_string()
    }

    pub(crate) fn rationale(&self) -> &str {
        &self.decision.rationale
    }

    pub(crate) fn source_label(&self) -> &'static str {
        match self.source {
            EffectiveReviewDecisionSource::SelectedFinding => "selected finding",
            EffectiveReviewDecisionSource::DurableIdentity => "durable identity",
        }
    }

    pub(crate) fn triage_verdict_label(&self) -> Option<&'static str> {
        self.decision
            .verdict
            .to_triage_verdict()
            .map(kuzushi_core::findings::TriageVerdict::as_str)
    }

    pub(crate) fn export_review_context(&self) -> WorkspaceFindingReviewContext {
        WorkspaceFindingReviewContext::from_carried_decision(
            self.decision.clone(),
            self.decision.verdict.to_triage_verdict(),
            self.carried_from_durable_identity(),
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct EffectiveReviewStateIndex {
    by_identity: BTreeMap<String, IndexedReviewDecision>,
    by_finding_id: BTreeMap<i64, IndexedReviewDecision>,
}

#[derive(Debug, Clone, PartialEq)]
struct IndexedReviewDecision {
    sort_key: ReviewSortKey,
    finding_id: Option<i64>,
    decision: ReviewDecision,
}

impl EffectiveReviewStateIndex {
    pub(crate) fn from_findings_and_decisions(
        findings: &[Finding],
        decisions: &[ReviewDecisionRecord],
    ) -> Self {
        let mut index = Self::default();
        for finding in findings {
            index.insert_finding_decision(finding);
        }
        for decision in decisions {
            index.insert_record_decision(decision);
        }
        index
    }

    fn insert_finding_decision(&mut self, finding: &Finding) {
        let Some(decision) = EffectiveReviewDecision::from_finding(finding) else {
            return;
        };
        let indexed = IndexedReviewDecision {
            sort_key: ReviewSortKey::from_finding(finding),
            finding_id: finding.id,
            decision: decision.decision,
        };
        if let Some(identity_id) = normalized_identity_id(finding) {
            insert_latest_decision(&mut self.by_identity, identity_id, indexed.clone());
        }
        if let Some(finding_id) = finding.id {
            insert_latest_decision(&mut self.by_finding_id, finding_id, indexed);
        }
    }

    fn insert_record_decision(&mut self, record: &ReviewDecisionRecord) {
        let indexed = IndexedReviewDecision {
            sort_key: ReviewSortKey::from_record(record),
            finding_id: Some(record.finding_id),
            decision: record.decision.clone(),
        };
        if let Some(identity_id) = normalized_record_identity_id(record) {
            insert_latest_decision(&mut self.by_identity, identity_id, indexed.clone());
        }
        insert_latest_decision(&mut self.by_finding_id, record.finding_id, indexed);
    }

    fn finding_decision_for(&self, finding: &Finding) -> Option<EffectiveReviewDecision> {
        finding
            .id
            .and_then(|finding_id| self.by_finding_id.get(&finding_id))
            .map(|indexed| EffectiveReviewDecision::from_indexed(indexed, finding))
    }

    fn identity_decision_for(&self, finding: &Finding) -> Option<EffectiveReviewDecision> {
        normalized_identity_id(finding)
            .as_deref()
            .and_then(|identity_id| self.by_identity.get(identity_id))
            .map(|indexed| EffectiveReviewDecision::from_indexed(indexed, finding))
    }

    pub(crate) fn effective_decision_for(
        &self,
        finding: &Finding,
    ) -> Option<EffectiveReviewDecision> {
        if normalized_identity_id(finding).is_some() {
            return self
                .identity_decision_for(finding)
                .or_else(|| EffectiveReviewDecision::from_finding(finding));
        }
        self.finding_decision_for(finding)
            .or_else(|| EffectiveReviewDecision::from_finding(finding))
    }

    pub(crate) fn verdict_for_identity(&self, identity_id: &str) -> Option<ReviewDecisionVerdict> {
        self.by_identity
            .get(identity_id.trim())
            .map(|indexed| indexed.decision.verdict)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ReviewSortKey {
    created_at: String,
    id: i64,
}

impl ReviewSortKey {
    fn from_finding(finding: &Finding) -> Self {
        Self {
            created_at: finding.created_at.clone(),
            id: finding.id.unwrap_or_default(),
        }
    }

    fn from_record(record: &ReviewDecisionRecord) -> Self {
        Self {
            created_at: record.created_at.clone(),
            id: record.id,
        }
    }
}

fn normalized_identity_id(finding: &Finding) -> Option<String> {
    finding
        .identity_id
        .as_deref()
        .map(str::trim)
        .filter(|identity_id| !identity_id.is_empty())
        .map(str::to_string)
}

fn normalized_record_identity_id(record: &ReviewDecisionRecord) -> Option<String> {
    record
        .identity_id
        .as_deref()
        .map(str::trim)
        .filter(|identity_id| !identity_id.is_empty())
        .map(str::to_string)
}

fn indexed_decision_source(
    finding: &Finding,
    indexed_finding_id: Option<i64>,
) -> EffectiveReviewDecisionSource {
    if finding.id.is_some() && finding.id == indexed_finding_id {
        EffectiveReviewDecisionSource::SelectedFinding
    } else {
        EffectiveReviewDecisionSource::DurableIdentity
    }
}

fn insert_latest_decision<K: Ord>(
    decisions: &mut BTreeMap<K, IndexedReviewDecision>,
    key: K,
    candidate: IndexedReviewDecision,
) {
    match decisions.get(&key) {
        Some(existing) if existing.sort_key > candidate.sort_key => {}
        _ => {
            decisions.insert(key, candidate);
        }
    }
}

pub(crate) fn current_review_decision(finding: &Finding) -> ReviewDecisionVerdict {
    finding
        .triage
        .as_ref()
        .map(|triage| ReviewDecision::from_triage(triage, finding.triaged_by).verdict)
        .unwrap_or_default()
}

pub(crate) fn review_decision_label(finding: &Finding) -> String {
    current_review_decision(finding).as_str().to_string()
}

pub(crate) fn review_decision_complete(finding: &Finding) -> bool {
    current_review_decision(finding).is_terminal()
}

pub(crate) fn effective_review_decision_label(
    finding: &Finding,
    decision: Option<&EffectiveReviewDecision>,
) -> String {
    decision
        .map(EffectiveReviewDecision::decision_label)
        .unwrap_or_else(|| review_decision_label(finding))
}

pub(crate) fn effective_review_decision_complete(
    finding: &Finding,
    decision: Option<&EffectiveReviewDecision>,
) -> bool {
    if effective_review_decision_conflict_label(finding, decision).is_some() {
        return false;
    }
    decision
        .map(EffectiveReviewDecision::complete)
        .unwrap_or_else(|| review_decision_complete(finding))
}

pub(crate) fn indexed_review_decision_complete(
    index: &EffectiveReviewStateIndex,
    finding: &Finding,
) -> bool {
    let decision = index.effective_decision_for(finding);
    effective_review_decision_complete(finding, decision.as_ref())
}

pub(crate) fn review_confidence_label(finding: &Finding) -> String {
    finding
        .triage
        .as_ref()
        .map(|triage| format!("{:.0}%", triage.confidence.clamp(0.0, 1.0) * 100.0))
        .unwrap_or_else(|| "-".to_string())
}

pub(crate) fn effective_review_confidence_label(
    finding: &Finding,
    decision: Option<&EffectiveReviewDecision>,
) -> String {
    decision
        .map(EffectiveReviewDecision::confidence_label)
        .unwrap_or_else(|| review_confidence_label(finding))
}

pub(crate) fn review_author_label(finding: &Finding) -> String {
    match (finding.triaged_by, finding.triage.as_ref()) {
        (Some(author), _) => author.as_str().to_string(),
        (None, Some(_)) => "auto".to_string(),
        (None, None) => "-".to_string(),
    }
}

pub(crate) fn effective_review_author_label(
    finding: &Finding,
    decision: Option<&EffectiveReviewDecision>,
) -> String {
    decision
        .map(EffectiveReviewDecision::author_label)
        .unwrap_or_else(|| review_author_label(finding))
}

pub(crate) fn lifecycle_status_label(finding: &Finding) -> String {
    finding_lifecycle_status(finding).to_string()
}

pub(crate) fn evidence_state_label(finding: &Finding) -> String {
    if !finding.evidence.is_empty() {
        return format!("evidence:{}", finding.evidence.len());
    }
    if finding.corroboration_count > 1 || finding.sources.len() > 1 {
        return "corroborated".to_string();
    }
    if !finding.sources.is_empty() || finding.source_signature.is_some() {
        return "source-linked".to_string();
    }
    "message-only".to_string()
}

#[cfg(test)]
#[path = "tests/review_state.rs"]
mod tests;
