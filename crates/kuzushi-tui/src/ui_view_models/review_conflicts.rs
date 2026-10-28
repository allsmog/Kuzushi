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
        "reappeared_after_rejection" => "other-observation",
        "not_reproduced_after_confirmation" => "not-reproduced",
        _ => "re-review",
    }
}

pub(crate) fn review_conflict_status_label(conflict: &str) -> &'static str {
    match conflict {
        "reappeared_after_rejection" => "check source",
        "runtime_verified_after_rejection" | "not_reproduced_after_confirmation" => "conflict",
        _ => "review",
    }
}

pub(crate) fn review_conflict_detail_label(conflict: &str) -> &'static str {
    match conflict {
        "runtime_verified_after_rejection" => {
            "runtime proof conflicts with a false-positive decision on another observation"
        }
        "reappeared_after_rejection" => {
            "the false-positive decision is based on a different recorded observation; check its source"
        }
        "not_reproduced_after_confirmation" => {
            "runtime proof did not reproduce a finding confirmed on another observation"
        }
        _ => "the displayed evidence differs from the recorded decision basis",
    }
}
