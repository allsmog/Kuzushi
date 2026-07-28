use super::*;

/// Encode a `VerificationOutcome` for the `verify:exploit` tool's JSON
/// response. Mirrors what `to_tool_json` does on other Kuzushi report
/// types.
pub fn to_tool_json(finding: &Finding, outcome: &VerificationOutcome) -> Value {
    let summary = verification_summary(outcome);
    let proof = verification_proof_snapshot(finding, outcome);
    let data = json!({
            "fingerprint": finding.fingerprint,
            "ruleId": finding.rule_id,
            "summary": summary,
            "proof": proof,
            "verification": outcome,
    });
    let mut response =
        crate::module_result::completed_output_result(summary.clone(), summary, data);
    add_verification_metadata(&mut response, proof, outcome.cost_usd);
    response
}

fn add_verification_metadata(response: &mut Value, proof: Value, cost_usd: f64) {
    if let Some(object) = response.as_object_mut() {
        object.insert("proof".to_string(), proof);
        object.insert("costUsd".to_string(), json!(cost_usd));
    }
}

fn verification_summary(outcome: &VerificationOutcome) -> String {
    format!(
        "verify:exploit proof_level={} verdict={}",
        outcome.proof_level,
        outcome.proof_verdict.as_str()
    )
}

fn verification_proof_snapshot(finding: &Finding, outcome: &VerificationOutcome) -> Value {
    json!({
        "kind": "verification-outcome",
        "fingerprint": finding.fingerprint,
        "ruleId": finding.rule_id,
        "proofLevel": outcome.proof_level,
        "proofVerdict": outcome.proof_verdict.as_str(),
        "backend": format!("{:?}", outcome.backend),
        "durationMs": outcome.duration_ms,
        "costUsd": outcome.cost_usd,
        "provenance": outcome.provenance,
    })
}
