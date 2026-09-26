//! Whether the review decision in force for one finding authorizes the proof
//! and remediation tools (`verify:finding`, `patch:finding`, `variant:hunt`).
//!
//! Those tools used to read only the automated triage cached on the finding
//! row, so an operator's recorded Review decision was invisible to them: the
//! shell showed a human-confirmed finding as ready to prove while the tool
//! refused it as untriaged. The gate below reads the same effective decision
//! that Review listings and proof deferral read, so a human verdict outranks
//! cached automated triage in every mode.

use super::super::domain::{Finding, ReviewDecision, TriageAuthor, TriageOutcome, TriageVerdict};
use super::effective_review_state::{
    review_verdict_is_actionable, EffectiveReviewDecision, EffectiveReviewStateIndex,
};
use crate::findings::FindingStore;
use anyhow::Result;

#[cfg(test)]
mod tests;

/// The review verdict in force for a finding, classified for tool gating.
#[derive(Debug, Clone, PartialEq)]
pub enum FindingReviewGate {
    /// The decision in force confirms the finding (`confirmed` or `to_fix`).
    Confirmed(ReviewConfirmation),
    /// A human or imported reviewer dismissed the finding.
    ReviewerDismissed(ReviewDecision),
    /// A decision is in force but it neither confirms nor was a reviewer
    /// dismissal (automated false positive, needs review, deferred).
    Unconfirmed(ReviewDecision),
    /// Neither automated triage nor any review decision exists.
    Unreviewed,
}

/// What confirmed a finding. The row's own automated triage keeps its full
/// structured outcome; any other confirmation stays a review decision so a
/// human verdict is never relabelled as model triage downstream.
#[derive(Debug, Clone, PartialEq)]
pub enum ReviewConfirmation {
    AutomatedTriage(TriageOutcome),
    ReviewDecision(ReviewDecision),
}

impl ReviewConfirmation {
    fn for_decision(finding: &Finding, decision: &ReviewDecision) -> Self {
        match finding.triage.as_ref() {
            Some(triage) if confirms_own_triage(decision, triage) => {
                Self::AutomatedTriage(triage.clone())
            }
            _ => Self::ReviewDecision(decision.clone()),
        }
    }
}

fn confirms_own_triage(decision: &ReviewDecision, triage: &TriageOutcome) -> bool {
    decision.author == TriageAuthor::Auto && triage.verdict == TriageVerdict::TruePositive
}

impl FindingReviewGate {
    /// Classify the effective decision resolved by
    /// [`EffectiveReviewStateIndex::effective_decision_for`], which already
    /// folds the finding's cached triage in; `None` therefore means the
    /// finding has neither triage nor a review decision.
    pub fn from_effective(finding: &Finding, decision: Option<&EffectiveReviewDecision>) -> Self {
        let Some(decision) = decision.map(EffectiveReviewDecision::review_decision) else {
            return Self::Unreviewed;
        };
        if review_verdict_is_actionable(decision.verdict) {
            return Self::Confirmed(ReviewConfirmation::for_decision(finding, decision));
        }
        if is_reviewer_dismissal(decision) {
            return Self::ReviewerDismissed(decision.clone());
        }
        Self::Unconfirmed(decision.clone())
    }
}

fn is_reviewer_dismissal(decision: &ReviewDecision) -> bool {
    decision.author != TriageAuthor::Auto && decision.effective_dismiss_reason().is_some()
}

/// The review decision in force for one finding, read from its store: the
/// same human-priority answer Review listings and proof gating use.
fn load_effective_review_decision(
    store: &FindingStore,
    finding: &Finding,
) -> Result<Option<EffectiveReviewDecision>> {
    let findings = std::slice::from_ref(finding);
    let decisions = store.list_review_decisions_for_findings(findings)?;
    let index = EffectiveReviewStateIndex::from_findings_and_decisions(findings, &decisions);
    Ok(index.effective_decision_for(finding))
}

/// Load and classify the review decision in force for tool gating.
pub fn load_finding_review_gate(
    store: &FindingStore,
    finding: &Finding,
) -> Result<FindingReviewGate> {
    let decision = load_effective_review_decision(store, finding)?;
    Ok(FindingReviewGate::from_effective(finding, decision.as_ref()))
}

/// Shared operator guidance when no triage or confirming decision exists.
pub const MISSING_CONFIRMATION_GUIDANCE: &str =
    "Run triage:run first, or record a confirmed or to_fix review decision.";
