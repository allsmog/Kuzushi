//! Which review decision currently governs a finding, and whether that
//! decision authorizes proof work.
//!
//! Append-only review records outlive the finding row they were written
//! against: a re-scan mints a new row for the same durable identity. Resolving
//! "the decision in force" therefore includes shared identity decisions and
//! decisions local to the selected row. Shell projections, headless review
//! listings, and the proof-deferral gate all read that one answer here so a
//! finding can never be actionable in one mode and unreviewed in another.
//!
//! Recency alone is not the tie-break. A human verdict outranks a machine one
//! whatever their order, so a later automated triage pass cannot quietly
//! overturn a decision an operator already made.

use super::super::domain::{
    Finding, ReviewDecision, ReviewDecisionRecord, ReviewDecisionVerdict, TriageAuthor,
    TriageVerdict,
};
use crate::workspace::WorkspaceFindingReviewContext;
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
mod tests;

/// The review decision in force for one finding, plus whether it was carried
/// from the durable identity rather than recorded against this exact row.
#[derive(Debug, Clone, PartialEq)]
pub struct EffectiveReviewDecision {
    decision: ReviewDecision,
    source: EffectiveReviewDecisionSource,
    record_id: Option<i64>,
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
            record_id: None,
        })
    }

    fn from_indexed(indexed: &IndexedReviewDecision, finding: &Finding) -> Self {
        Self {
            decision: indexed.decision.clone(),
            source: indexed_decision_source(finding, indexed.finding_id),
            record_id: indexed.record_id,
        }
    }

    /// A decision carried onto a finding from its durable identity. Exposed so
    /// callers can exercise carried-decision presentation without staging a
    /// whole re-scan ledger.
    pub fn carried_from_identity(decision: ReviewDecision) -> Self {
        Self {
            decision,
            source: EffectiveReviewDecisionSource::DurableIdentity,
            record_id: None,
        }
    }

    pub fn verdict(&self) -> ReviewDecisionVerdict {
        self.decision.verdict
    }

    pub fn review_decision(&self) -> &ReviewDecision {
        &self.decision
    }

    /// Exact immutable record chosen by the shared resolver. Embedded legacy
    /// triage has no record and must not manufacture event provenance.
    pub fn record_id(&self) -> Option<i64> {
        self.record_id
    }

    pub fn carried_from_durable_identity(&self) -> bool {
        self.source == EffectiveReviewDecisionSource::DurableIdentity
    }

    pub fn decision_label(&self) -> String {
        self.decision.verdict.as_str().to_string()
    }

    pub fn complete(&self) -> bool {
        self.decision.verdict.is_terminal()
    }

    pub fn confidence_label(&self) -> String {
        format!("{:.0}%", self.decision.confidence.clamp(0.0, 1.0) * 100.0)
    }

    pub fn author_label(&self) -> String {
        self.decision.author.as_str().to_string()
    }

    pub fn rationale(&self) -> &str {
        &self.decision.rationale
    }

    pub fn source_label(&self) -> &'static str {
        match self.source {
            EffectiveReviewDecisionSource::SelectedFinding => "selected finding",
            EffectiveReviewDecisionSource::DurableIdentity => "durable identity",
        }
    }

    pub fn triage_verdict_label(&self) -> Option<&'static str> {
        self.decision
            .verdict
            .to_triage_verdict()
            .map(TriageVerdict::as_str)
    }

    pub fn export_review_context(&self) -> WorkspaceFindingReviewContext {
        WorkspaceFindingReviewContext::from_carried_decision(
            self.decision.clone(),
            self.decision.verdict.to_triage_verdict(),
            self.carried_from_durable_identity(),
        )
    }
}

/// Human-priority, then newest-decision index over a whole ledger. Local
/// records apply only to their finding row; identity records may be carried.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EffectiveReviewStateIndex {
    by_identity: BTreeMap<String, IndexedReviewDecision>,
    by_finding_id: BTreeMap<i64, IndexedReviewDecision>,
    by_local_finding_id: BTreeMap<i64, IndexedReviewDecision>,
}

#[derive(Debug, Clone, PartialEq)]
struct IndexedReviewDecision {
    sort_key: ReviewSortKey,
    finding_id: Option<i64>,
    decision: ReviewDecision,
    record_id: Option<i64>,
}

impl EffectiveReviewStateIndex {
    pub fn from_findings_and_decisions(
        findings: &[Finding],
        decisions: &[ReviewDecisionRecord],
    ) -> Self {
        let mut index = Self::default();
        let local_rows = decisions
            .iter()
            .filter(|record| normalized_record_identity_id(record).is_none())
            .map(|record| record.finding_id)
            .collect::<BTreeSet<_>>();
        for finding in findings {
            let local = finding.id.is_some_and(|id| local_rows.contains(&id));
            index.insert_finding_decision(finding, local);
        }
        for decision in decisions {
            index.insert_record_decision(decision);
        }
        index
    }

    fn insert_finding_decision(&mut self, finding: &Finding, local: bool) {
        let Some(decision) = EffectiveReviewDecision::from_finding(finding) else {
            return;
        };
        let indexed = IndexedReviewDecision {
            sort_key: ReviewSortKey::from_finding(finding),
            finding_id: finding.id,
            decision: decision.decision,
            record_id: None,
        };
        self.insert_embedded_decision_scope(finding, &indexed, local);
        if let Some(finding_id) = finding.id {
            insert_latest_decision(&mut self.by_finding_id, finding_id, indexed);
        }
    }

    fn insert_embedded_decision_scope(
        &mut self,
        finding: &Finding,
        indexed: &IndexedReviewDecision,
        local: bool,
    ) {
        // A cached triage value carries no scope metadata. An explicit local
        // record prevents that cache from manufacturing identity propagation.
        if local {
            if let Some(id) = finding.id {
                insert_latest_decision(&mut self.by_local_finding_id, id, indexed.clone());
            }
            return;
        }
        if let Some(identity) = normalized_identity_id(finding) {
            insert_latest_decision(&mut self.by_identity, identity, indexed.clone());
        }
    }

    fn insert_record_decision(&mut self, record: &ReviewDecisionRecord) {
        let indexed = IndexedReviewDecision {
            sort_key: ReviewSortKey::from_record(record),
            finding_id: Some(record.finding_id),
            decision: record.decision.clone(),
            record_id: Some(record.id),
        };
        if let Some(identity_id) = normalized_record_identity_id(record) {
            insert_latest_decision(&mut self.by_identity, identity_id, indexed.clone());
        } else {
            insert_latest_decision(
                &mut self.by_local_finding_id,
                record.finding_id,
                indexed.clone(),
            );
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
        let identity = normalized_identity_id(finding)
            .as_deref()
            .and_then(|identity_id| self.by_identity.get(identity_id));
        let local = finding.id.and_then(|id| self.by_local_finding_id.get(&id));
        effective_indexed_decision(identity, local)
            .map(|indexed| EffectiveReviewDecision::from_indexed(indexed, finding))
    }

    pub fn effective_decision_for(&self, finding: &Finding) -> Option<EffectiveReviewDecision> {
        if normalized_identity_id(finding).is_some() {
            return self
                .identity_decision_for(finding)
                .or_else(|| EffectiveReviewDecision::from_finding(finding));
        }
        self.finding_decision_for(finding)
            .or_else(|| EffectiveReviewDecision::from_finding(finding))
    }

    pub fn verdict_for_identity(&self, identity_id: &str) -> Option<ReviewDecisionVerdict> {
        self.by_identity
            .get(identity_id.trim())
            .map(|indexed| indexed.decision.verdict)
    }
}

/// Every applicable identity or finding-local decision, newest first.
pub fn review_decision_history_for<'a>(
    finding: &Finding,
    records: &'a [ReviewDecisionRecord],
) -> Vec<&'a ReviewDecisionRecord> {
    let identity_id = normalized_identity_id(finding);
    let mut matching = records
        .iter()
        .filter(|record| record_addresses_finding(record, finding, identity_id.as_deref()))
        .collect::<Vec<_>>();
    matching.sort_by(|left, right| {
        ReviewSortKey::from_record(right).cmp(&ReviewSortKey::from_record(left))
    });
    matching
}

fn record_addresses_finding(
    record: &ReviewDecisionRecord,
    finding: &Finding,
    identity_id: Option<&str>,
) -> bool {
    match (
        identity_id,
        normalized_record_identity_id(record).as_deref(),
    ) {
        (Some(identity), Some(record_identity)) => identity == record_identity,
        _ => finding.id == Some(record.finding_id),
    }
}

fn effective_indexed_decision<'a>(
    identity: Option<&'a IndexedReviewDecision>,
    local: Option<&'a IndexedReviewDecision>,
) -> Option<&'a IndexedReviewDecision> {
    match (identity, local) {
        (Some(shared), Some(local)) if decision_remains_effective(shared, local) => Some(shared),
        (_, Some(local)) => Some(local),
        (shared, None) => shared,
    }
}

/// Whether a review verdict authorizes proof and remediation work on the
/// finding. Only an operator-confirmed or to-fix verdict does.
pub const fn review_verdict_is_actionable(verdict: ReviewDecisionVerdict) -> bool {
    matches!(
        verdict,
        ReviewDecisionVerdict::Confirmed | ReviewDecisionVerdict::ToFix
    )
}

/// The actionability answer for a finding whose effective decision is already
/// resolved. `None` falls back to the finding's own triage verdict.
pub fn decision_is_review_actionable(
    finding: &Finding,
    decision: Option<&EffectiveReviewDecision>,
) -> bool {
    match decision {
        Some(decision) => review_verdict_is_actionable(decision.verdict()),
        None => finding
            .triage
            .as_ref()
            .is_some_and(|triage| triage.verdict == TriageVerdict::TruePositive),
    }
}

/// Whether one finding is review-actionable given the append-only decision
/// records for its ledger.
pub fn finding_is_review_actionable(finding: &Finding, decisions: &[ReviewDecisionRecord]) -> bool {
    let index = EffectiveReviewStateIndex::from_findings_and_decisions(
        std::slice::from_ref(finding),
        decisions,
    );
    decision_is_review_actionable(finding, index.effective_decision_for(finding).as_ref())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ReviewSortKey {
    Embedded { created_at: String, id: i64 },
    LegacyRecord { id: i64, created_at: String },
    Recorded { event_seq: u64, id: i64 },
}

impl ReviewSortKey {
    fn from_finding(finding: &Finding) -> Self {
        Self::Embedded {
            created_at: finding.created_at.clone(),
            id: finding.id.unwrap_or_default(),
        }
    }

    fn from_record(record: &ReviewDecisionRecord) -> Self {
        match &record.provenance {
            Some(provenance) => Self::Recorded {
                event_seq: provenance.event_seq,
                id: record.id,
            },
            None => Self::LegacyRecord {
                id: record.id,
                created_at: record.created_at.clone(),
            },
        }
    }
}

fn normalized_identity_id(finding: &Finding) -> Option<String> {
    normalized_identity(finding.identity_id.as_deref())
}

fn normalized_record_identity_id(record: &ReviewDecisionRecord) -> Option<String> {
    normalized_identity(record.identity_id.as_deref())
}

fn normalized_identity(identity_id: Option<&str>) -> Option<String> {
    identity_id
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
        Some(existing) if decision_remains_effective(existing, &candidate) => {}
        _ => {
            decisions.insert(key, candidate);
        }
    }
}

/// A human decision holds against a machine one regardless of recency; between
/// two decisions by the same kind of author, the newer one wins.
fn decision_remains_effective(
    existing: &IndexedReviewDecision,
    candidate: &IndexedReviewDecision,
) -> bool {
    match (
        existing.decision.author == TriageAuthor::Human,
        candidate.decision.author == TriageAuthor::Human,
    ) {
        (true, false) => true,
        (false, true) => false,
        _ => existing.sort_key > candidate.sort_key,
    }
}
