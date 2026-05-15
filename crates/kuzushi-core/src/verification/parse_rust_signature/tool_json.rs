use super::*;

/// Encode a `VerificationOutcome` for the `verify:exploit` tool's JSON
/// response. Mirrors what `to_tool_json` does on other Kuzushi report
/// types.
pub fn to_tool_json(finding: &Finding, outcome: &VerificationOutcome) -> Value {
    let summary = verification_summary(outcome);
    let proof = verification_proof_snapshot(finding, outcome);
    json!({
        "ok": true,
        "status": "completed",
        "summary": summary,
        "output": summary,
        "artifacts": [],
        "warnings": [],
        "errors": [],
        "proof": proof,
        "costUsd": outcome.cost_usd,
        "data": {
            "fingerprint": finding.fingerprint,
            "ruleId": finding.rule_id,
            "summary": summary,
            "proof": proof,
            "verification": outcome,
        }
    })
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
    })
}
