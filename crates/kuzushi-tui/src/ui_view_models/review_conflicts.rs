use super::review_state::EffectiveReviewDecision;
use kuzushi_core::findings::ReviewDecisionConflict;
use kuzushi_core::Finding;

pub(crate) fn effective_review_decision_conflict_label(
    finding: &Finding,
    decision: Option<&EffectiveReviewDecision>,
) -> Option<String> {
    let decision = decision?;
    ReviewDecisionConflict::classify(
        finding,
        decision.verdict(),
        decision.carried_from_durable_identity(),
    )
    .map(|conflict| conflict.export_token().to_string())
}

pub(crate) fn review_conflict_compact_label(conflict: &str) -> &'static str {
    match conflict {
        "runtime_verified_after_rejection" => "runtime-verified",
        "reappeared_after_rejection" => "scanner-reappeared",
        "not_reproduced_after_confirmation" => "not-reproduced",
        _ => "re-review",
    }
}

pub(crate) fn review_conflict_detail_label(conflict: &str) -> &'static str {
    match conflict {
        "runtime_verified_after_rejection" => {
            "runtime proof contradicts an earlier false-positive decision"
        }
        "reappeared_after_rejection" => {
            "a scanner reported this finding again after an earlier false-positive decision"
        }
        "not_reproduced_after_confirmation" => {
            "runtime proof did not reproduce an earlier confirmed finding"
        }
        _ => "the current evidence conflicts with an earlier decision",
    }
}
