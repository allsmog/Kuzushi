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
            "exploitable": outcome.proof_verdict == ProofVerdict::Exploited,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empirical_tool_json_exposes_patch_eligibility_without_reinterpreting_proof() {
        let finding = Finding::new_tool(
            "fixture",
            "fixture/cwe-787",
            "src/lib.rs",
            10,
            None,
            crate::findings::Severity::High,
            "fixture",
        );
        let outcome = VerificationOutcome {
            proof_level: 4,
            proof_verdict: ProofVerdict::Exploited,
            backend: SandboxBackend::Bwrap,
            language: Some("rust".to_string()),
            harness_path: None,
            crash_evidence: Some("sink reached".to_string()),
            duration_ms: 10,
            cost_usd: 0.0,
            notes: Vec::new(),
            provenance: None,
        };

        let output = to_tool_json(&finding, &outcome);

        assert_eq!(output.pointer("/data/exploitable"), Some(&json!(true)));
        assert_eq!(
            output.pointer("/data/proof/proofVerdict"),
            Some(&json!("exploited"))
        );
    }
}
