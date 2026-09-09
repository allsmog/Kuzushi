use super::review_conflicts::effective_review_decision_conflict_label;
use kuzushi_core::findings::{finding_lifecycle_status, ReviewDecision, ReviewDecisionVerdict};
use kuzushi_core::Finding;

// One resolution of "which review decision is in force" is shared with the
// headless CLI; the shell only projects it.
pub(crate) use kuzushi_core::findings::{
    decision_is_review_actionable, review_decision_history_for, EffectiveReviewDecision,
    EffectiveReviewStateIndex,
};

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
        return "multiple observations".to_string();
    }
    if !finding.sources.is_empty() || finding.source_signature.is_some() {
        return "source-linked".to_string();
    }
    "message-only".to_string()
}

#[cfg(test)]
#[path = "tests/review_state.rs"]
mod tests;
