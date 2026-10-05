//! Which findings `verify:finding` agrees to assess, decided from the review
//! decision in force rather than the cached automated triage alone.

use crate::findings::{Finding, FindingReviewGate, ReviewDecision};
use serde_json::{json, Value};

/// Verification needs a reason to believe the finding is real: automated
/// triage of any verdict (a model-assessed false positive may be challenged)
/// or a confirming review decision. A reviewer's dismissal is final here; the
/// operator reopens the finding by recording a new decision.
pub(super) fn verify_review_gate_refusal(
    finding: &Finding,
    gate: &FindingReviewGate,
) -> Option<Value> {
    match gate {
        FindingReviewGate::Confirmed(_) => None,
        FindingReviewGate::ReviewerDismissed(decision) => {
            Some(dismissed_finding_response(&finding.fingerprint, decision))
        }
        _ if finding.triage.is_some() => None,
        _ => Some(unconfirmed_finding_response(&finding.fingerprint)),
    }
}

fn unconfirmed_finding_response(fingerprint: &str) -> Value {
    let output = format!(
        "[-] Finding '{fingerprint}' has no triage verdict and no confirming review decision. {}",
        crate::findings::MISSING_CONFIRMATION_GUIDANCE
    );
    refused_verify_response(
        json!({ "fingerprint": fingerprint, "reason": "missing-triage" }),
        output,
    )
}

fn dismissed_finding_response(fingerprint: &str, decision: &ReviewDecision) -> Value {
    let output = format!(
        "[-] Finding '{fingerprint}' was dismissed by a {author} review decision ({verdict}); verification is not needed. Record a new review decision to reopen it.",
        author = decision.author.as_str(),
        verdict = decision.verdict.as_str(),
    );
    let data = json!({
        "fingerprint": fingerprint,
        "reason": "reviewer-dismissed",
        "reviewDecision": decision.verdict.as_str(),
        "reviewAuthor": decision.author.as_str(),
    });
    refused_verify_response(data, output)
}

fn refused_verify_response(data: Value, output: String) -> Value {
    crate::module_result::failed_output_result("verify:finding failed", output, data)
}

#[cfg(test)]
mod tests;
