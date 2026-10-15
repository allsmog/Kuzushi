use super::*;
use crate::findings::{FindingReviewGate, ReviewConfirmation, ReviewDecision};

pub(crate) fn variant_confirmation(
    tool: &str,
    fingerprint: &str,
    gate: FindingReviewGate,
) -> std::result::Result<ReviewConfirmation, Value> {
    match gate {
        FindingReviewGate::Confirmed(confirmation) => Ok(confirmation),
        FindingReviewGate::Unreviewed => Err(unreviewed_response(tool, fingerprint)),
        FindingReviewGate::ReviewerDismissed(decision)
        | FindingReviewGate::Unconfirmed(decision) => {
            Err(unconfirmed_response(tool, fingerprint, &decision))
        }
    }
}

fn unreviewed_response(tool: &str, fingerprint: &str) -> Value {
    crate::module_result::failed_output_result(
        format!("{tool} finding is not confirmed"),
        format!("{tool} expects a confirmed TP; finding \"{fingerprint}\" has no triage verdict and no confirming review decision. {}", crate::findings::MISSING_CONFIRMATION_GUIDANCE),
        json!({"fingerprint":fingerprint,"reason":"missing-triage"}),
    )
}

fn unconfirmed_response(tool: &str, fingerprint: &str, decision: &ReviewDecision) -> Value {
    let verdict = decision
        .verdict
        .to_triage_verdict()
        .map_or(decision.verdict.as_str(), TriageVerdict::as_str);
    crate::module_result::failed_output_result(
        format!("{tool} finding is not confirmed"),
        format!("{tool} expects a confirmed TP; finding \"{fingerprint}\" has review decision \"{}\" by {}.", decision.verdict.as_str(),decision.author.as_str()),
        json!({"fingerprint":fingerprint,"reason":"non-true-positive","verdict":verdict,
            "reviewDecision":decision.verdict.as_str(),"reviewAuthor":decision.author.as_str()}),
    )
}

#[cfg(test)]
mod tests;
