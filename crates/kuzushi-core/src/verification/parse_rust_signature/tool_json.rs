use super::*;

/// Encode a `VerificationOutcome` for the `verify:exploit` tool's JSON
/// response. Mirrors what `to_tool_json` does on other Kuzushi report
/// types.
pub fn to_tool_json(finding: &Finding, outcome: &VerificationOutcome) -> Value {
    json!({
        "ok": true,
        "data": {
            "fingerprint": finding.fingerprint,
            "ruleId": finding.rule_id,
            "verification": outcome,
        }
    })
}
