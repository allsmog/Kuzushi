use crate::findings::ReviewDecision;
use serde_json::{json, Value};

pub(super) fn missing_patch_finding_response(fingerprint: &str) -> Value {
    let output = format!("[-] No finding with fingerprint '{fingerprint}'.");
    refused_patch_response(output, refusal_data(fingerprint, "missing-finding"))
}

pub(super) fn untriaged_patch_finding_response(fingerprint: &str) -> Value {
    let output = format!(
        "[-] Finding '{fingerprint}' has no triage verdict and no confirming review decision. {}",
        crate::findings::MISSING_CONFIRMATION_GUIDANCE
    );
    refused_patch_response(output, refusal_data(fingerprint, "missing-triage"))
}

pub(super) fn unconfirmed_patch_finding_response(
    fingerprint: &str,
    decision: &ReviewDecision,
) -> Value {
    let output = format!(
        "[-] Finding '{fingerprint}' is not confirmed true_positive (review decision in force: {verdict} by {author}); patch:finding only patches confirmed findings.",
        verdict = decision.verdict.as_str(),
        author = decision.author.as_str(),
    );
    let data = json!({
        "fingerprint": fingerprint,
        "reason": "not-confirmed-true-positive",
        "reviewDecision": decision.verdict.as_str(),
        "reviewAuthor": decision.author.as_str(),
    });
    refused_patch_response(output, data)
}

fn refusal_data(fingerprint: &str, reason: &str) -> Value {
    json!({
        "fingerprint": fingerprint,
        "reason": reason,
    })
}

fn refused_patch_response(output: String, data: Value) -> Value {
    crate::module_result::failed_output_result("patch:finding failed", output, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_patch_response_uses_failed_result_envelope() {
        let response = missing_patch_finding_response("missing");

        assert_eq!(response["ok"], json!(false));
        assert_eq!(response["status"], json!("failed"));
        assert_eq!(response["summary"], json!("patch:finding failed"));
        assert_eq!(response["data"]["reason"], json!("missing-finding"));
        assert!(response["errors"][0]
            .as_str()
            .unwrap()
            .contains("No finding with fingerprint 'missing'"));
    }
}
