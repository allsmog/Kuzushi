use super::json_fields::{
    normalize_attack_path, normalize_code_citations, normalize_controls, normalize_object_array,
    read_object_bool, read_object_f64, read_object_nullable_string, read_object_string,
    read_object_string_array, read_object_u64, string_or_null,
};
use crate::findings::{Finding, TriageOutcome};
use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

pub(in crate::verification::adapters) fn build_verify_prompt(
    finding: &Finding,
    triage: &TriageOutcome,
    template: Option<&str>,
) -> Result<String> {
    let finding_json =
        serde_json::to_string_pretty(finding).context("Could not serialize finding")?;
    let triage_json = serde_json::to_string_pretty(triage).context("Could not serialize triage")?;
    let prefix = template
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(
            "Verify exploitability for this triaged finding. Be conservative and return non-exploitable when runtime evidence is incomplete.",
        );
    Ok(format!(
        "{prefix}\n\nFinding JSON:\n{finding_json}\n\nTriage JSON:\n{triage_json}"
    ))
}

pub(in crate::verification::adapters) fn normalize_verification_result(
    raw: Value,
    fallback_fingerprint: &str,
) -> Result<Value> {
    let Value::Object(object) = raw else {
        anyhow::bail!("verification output parse failed: expected a JSON object");
    };

    let fingerprint = read_object_string(&object, &["fingerprint"])
        .unwrap_or_else(|| fallback_fingerprint.to_string());
    let exploitable = read_object_bool(&object, &["exploitable"]).unwrap_or(false);
    let poc_payload = read_object_nullable_string(&object, &["pocPayload", "poc_payload"]);
    let poc_description =
        read_object_string(&object, &["pocDescription", "poc_description"]).unwrap_or_default();
    let attack_vector = read_object_nullable_string(&object, &["attackVector", "attack_vector"]);
    let preconditions = read_object_string_array(&object, &["preconditions"]);
    let confidence = read_object_f64(&object, &["confidence"])
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);

    let mut result = Map::new();
    result.insert("fingerprint".to_string(), json!(fingerprint));
    result.insert("exploitable".to_string(), json!(exploitable));
    result.insert("pocPayload".to_string(), string_or_null(poc_payload));
    result.insert("pocDescription".to_string(), json!(poc_description));
    result.insert("attackVector".to_string(), string_or_null(attack_vector));
    result.insert("preconditions".to_string(), json!(preconditions));
    result.insert("confidence".to_string(), json!(confidence));

    if let Some(level) = read_object_u64(&object, &["proofLevel", "proof_level"])
        .filter(|level| (1..=4).contains(level))
    {
        result.insert("proofLevel".to_string(), json!(level));
    }
    if let Some(verdict) = read_object_string(&object, &["proofVerdict", "proof_verdict"]) {
        result.insert("proofVerdict".to_string(), json!(verdict));
    }
    if let Some(value) = normalize_object_array(&object, &["bypassAttempts", "bypass_attempts"]) {
        result.insert("bypassAttempts".to_string(), value);
    }
    if let Some(value) = normalize_code_citations(&object) {
        result.insert("codeCitations".to_string(), value);
    }
    if let Some(value) = normalize_attack_path(&object) {
        result.insert("attackPath".to_string(), value);
    }
    if let Some(value) = normalize_object_array(&object, &["assumptions"]) {
        result.insert("assumptions".to_string(), value);
    }
    if let Some(value) = normalize_controls(&object) {
        result.insert("controls".to_string(), value);
    }
    if let Some(value) = normalize_object_array(&object, &["blindspots"]) {
        result.insert("blindspots".to_string(), value);
    }

    Ok(Value::Object(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;

    #[test]
    fn normalizes_verification_result_aliases_and_clamps_confidence() {
        let result = normalize_verification_result(
            json!({
                "exploitable": true,
                "poc_payload": "curl /admin",
                "poc_description": "reachable admin action",
                "attack_vector": "HTTP POST",
                "preconditions": [" authenticated "],
                "confidence": 1.5,
                "proof_level": 4,
                "proof_verdict": "exploited",
                "bypass_attempts": ["csrf token replay"],
                "code_citations": [{
                    "file_path": "src/admin.rs",
                    "start_line": 44,
                    "description": "sink"
                }]
            }),
            "fallback-fp",
        )
        .unwrap();

        assert_eq!(result["fingerprint"], "fallback-fp");
        assert_eq!(result["exploitable"], true);
        assert_eq!(result["pocPayload"], "curl /admin");
        assert_eq!(result["attackVector"], "HTTP POST");
        assert_eq!(result["confidence"], 1.0);
        assert_eq!(result["proofLevel"], 4);
        assert_eq!(result["codeCitations"][0]["filePath"], "src/admin.rs");
    }

    #[test]
    fn rejects_non_object_verification_output() {
        let err = normalize_verification_result(json!(["nope"]), "fp")
            .unwrap_err()
            .to_string();

        assert!(err.contains("expected a JSON object"));
    }

    #[test]
    fn builds_prompt_with_template_and_payloads() {
        let finding = Finding::new_tool(
            "semgrep",
            "demo.rule",
            "src/db.rs",
            7,
            None,
            Severity::High,
            "SQL injection",
        );
        let triage = TriageOutcome {
            rationale: "confirmed".to_string(),
            ..Default::default()
        };

        let prompt = build_verify_prompt(&finding, &triage, Some("Custom verify")).unwrap();

        assert!(prompt.starts_with("Custom verify"));
        assert!(prompt.contains("SQL injection"));
        assert!(prompt.contains("confirmed"));
    }
}
