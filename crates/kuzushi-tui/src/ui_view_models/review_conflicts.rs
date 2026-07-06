use super::review_state::EffectiveReviewDecision;
use kuzushi_core::findings::{finding_lifecycle_status, ReviewDecisionVerdict};
use kuzushi_core::Finding;

pub(crate) fn effective_review_decision_conflict_label(
    finding: &Finding,
    decision: Option<&EffectiveReviewDecision>,
) -> Option<String> {
    let decision = decision?;
    if !decision.carried_from_durable_identity() {
        return None;
    }
    if decision.verdict() != ReviewDecisionVerdict::RejectedFalsePositive {
        return None;
    }
    active_scanner_signal(finding).then(|| "reappeared_after_rejection".to_string())
}

fn active_scanner_signal(finding: &Finding) -> bool {
    matches!(
        finding_lifecycle_status(finding),
        "candidate"
            | "seen"
            | "statically_supported"
            | "verified_static"
            | "needs_runtime_evidence"
            | "runtime_verified"
    )
}
