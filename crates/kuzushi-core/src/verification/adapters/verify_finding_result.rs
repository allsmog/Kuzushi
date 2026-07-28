use super::json_fields::{
    normalize_attack_path, normalize_code_citations, normalize_controls, normalize_object_array,
    read_object_nullable_string, read_object_string, read_object_string_array, read_object_u64,
    read_object_value, string_or_null,
};
use crate::findings::Finding;
use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

pub(crate) const DEFAULT_VERIFY_PROMPT: &str = "Treat this finding as a false positive until proven otherwise. Read the actual code at the cited location, then search for a reason it CANNOT be exploited — input validation, sanitization, an authentication or authorization gate, a type or length constraint, unreachable code, or no attacker control over the tainted input. Return exploitable=true only when attacker-controlled input reaches the sink with no blocking control in between; return exploitable=false when the evidence is incomplete.";

/// Build the prompt for the independent exploitability verifier.
///
/// Deliberately context-isolated: the verifier receives only the *claim*
/// (vuln class, location, evidence) and the codebase — never the
/// discovery/triage agent's verdict or rationale. Feeding the verifier
/// the finder's reasoning makes it agree instead of testing the claim,
/// which is the dominant source of non-exploitable findings slipping
/// through. The default framing is adversarial: assume false positive,
/// hunt for the mitigation, confirm only when it cannot be disproved.
pub(in crate::verification::adapters) fn build_verify_prompt(
    finding: &Finding,
    template: Option<&str>,
) -> Result<String> {
    let claim_json = serde_json::to_string_pretty(&independent_finding_claim(finding)?)
        .context("Could not serialize finding claim")?;
    let prefix = template
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_VERIFY_PROMPT);
    Ok(format!("{prefix}\n\nClaimed finding:\n{claim_json}"))
}

/// Strip the discovery/triage reasoning (and any prior verification) from
/// a finding so the verifier sees the claim without the argument for it.
fn independent_finding_claim(finding: &Finding) -> Result<Value> {
    let mut value = serde_json::to_value(finding).context("Could not serialize finding")?;
    if let Value::Object(object) = &mut value {
        object.remove("triage");
        object.remove("verification");
    }
    Ok(value)
}

pub(in crate::verification::adapters) fn normalize_verification_result(
    raw: Value,
    fallback_fingerprint: &str,
) -> Result<Value> {
    let Value::Object(object) = raw else {
        anyhow::bail!("verification output parse failed: expected a JSON object");
    };
    let required = required_verification_fields(&object, fallback_fingerprint)?;
    let mut result = Map::new();
    insert_required_verification_fields(&mut result, required);
    insert_optional_verification_fields(&mut result, &object);
    Ok(Value::Object(result))
}

struct RequiredVerificationFields {
    fingerprint: String,
    exploitable: bool,
    poc_payload: Option<String>,
    poc_description: String,
    attack_vector: Option<String>,
    preconditions: Vec<String>,
    confidence: f64,
}

fn required_verification_fields(
    object: &Map<String, Value>,
    fallback_fingerprint: &str,
) -> Result<RequiredVerificationFields> {
    let fingerprint = canonical_verification_fingerprint(object, fallback_fingerprint)?;
    let exploitable = required_object_bool(object, &["exploitable"])?;
    let poc_payload = read_object_nullable_string(object, &["pocPayload", "poc_payload"]);
    let poc_description =
        read_object_string(object, &["pocDescription", "poc_description"]).unwrap_or_default();
    let attack_vector = read_object_nullable_string(object, &["attackVector", "attack_vector"]);
    let preconditions = read_object_string_array(object, &["preconditions"]);
    let confidence = required_object_f64(object, &["confidence"])?.clamp(0.0, 1.0);

    Ok(RequiredVerificationFields {
        fingerprint,
        exploitable,
        poc_payload,
        poc_description,
        attack_vector,
        preconditions,
        confidence,
    })
}

fn canonical_verification_fingerprint(
    object: &Map<String, Value>,
    requested_fingerprint: &str,
) -> Result<String> {
    let Some(value) = object.get("fingerprint") else {
        return Ok(requested_fingerprint.to_string());
    };
    let Value::String(model_fingerprint) = value else {
        anyhow::bail!(
            "verification output fingerprint must be a non-empty string, got {}",
            value_type_name(value)
        );
    };
    let model_fingerprint = model_fingerprint.trim();
    anyhow::ensure!(
        !model_fingerprint.is_empty(),
        "verification output fingerprint must be a non-empty string"
    );
    anyhow::ensure!(
        model_fingerprint == requested_fingerprint,
        "verification output fingerprint mismatch: requested `{requested_fingerprint}`, received `{model_fingerprint}`"
    );
    Ok(requested_fingerprint.to_string())
}

fn insert_required_verification_fields(
    result: &mut Map<String, Value>,
    fields: RequiredVerificationFields,
) {
    result.insert("fingerprint".to_string(), json!(fields.fingerprint));
    result.insert("exploitable".to_string(), json!(fields.exploitable));
    result.insert("pocPayload".to_string(), string_or_null(fields.poc_payload));
    result.insert("pocDescription".to_string(), json!(fields.poc_description));
    result.insert(
        "attackVector".to_string(),
        string_or_null(fields.attack_vector),
    );
    result.insert("preconditions".to_string(), json!(fields.preconditions));
    result.insert("confidence".to_string(), json!(fields.confidence));
}

fn insert_optional_verification_fields(
    result: &mut Map<String, Value>,
    object: &Map<String, Value>,
) {
    insert_optional_proof_fields(result, object);
    insert_optional_evidence_fields(result, object);
    insert_optional_context_fields(result, object);
}

fn insert_optional_proof_fields(result: &mut Map<String, Value>, object: &Map<String, Value>) {
    if let Some(level) = read_object_u64(object, &["proofLevel", "proof_level"])
        .filter(|level| (1..=4).contains(level))
    {
        result.insert("proofLevel".to_string(), json!(level));
    }
    if let Some(verdict) = read_object_string(object, &["proofVerdict", "proof_verdict"]) {
        result.insert("proofVerdict".to_string(), json!(verdict));
    }
}

fn insert_optional_evidence_fields(result: &mut Map<String, Value>, object: &Map<String, Value>) {
    if let Some(value) = normalize_object_array(object, &["bypassAttempts", "bypass_attempts"]) {
        result.insert("bypassAttempts".to_string(), value);
    }
    if let Some(value) = normalize_code_citations(object) {
        result.insert("codeCitations".to_string(), value);
    }
    if let Some(value) = normalize_attack_path(object) {
        result.insert("attackPath".to_string(), value);
    }
}

fn insert_optional_context_fields(result: &mut Map<String, Value>, object: &Map<String, Value>) {
    if let Some(value) = normalize_object_array(object, &["assumptions"]) {
        result.insert("assumptions".to_string(), value);
    }
    if let Some(value) = normalize_controls(object) {
        result.insert("controls".to_string(), value);
    }
    if let Some(value) = normalize_object_array(object, &["blindspots"]) {
        result.insert("blindspots".to_string(), value);
    }
}

fn required_object_bool(object: &Map<String, Value>, keys: &[&str]) -> Result<bool> {
    let value = read_object_value(object, keys).ok_or_else(|| {
        anyhow::anyhow!("verification output missing required boolean `exploitable`")
    })?;
    value.as_bool().ok_or_else(|| {
        anyhow::anyhow!(
            "verification output field `exploitable` must be boolean, got {}",
            value_type_name(value)
        )
    })
}

fn required_object_f64(object: &Map<String, Value>, keys: &[&str]) -> Result<f64> {
    let value = read_object_value(object, keys).ok_or_else(|| {
        anyhow::anyhow!("verification output missing required number `confidence`")
    })?;
    value.as_f64().ok_or_else(|| {
        anyhow::anyhow!(
            "verification output field `confidence` must be number, got {}",
            value_type_name(value)
        )
    })
}

fn value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Severity, TriageOutcome};

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
    fn rejects_model_fingerprint_that_does_not_match_requested_finding() {
        let error = normalize_verification_result(
            json!({
                "fingerprint": "hallucinated-fingerprint",
                "exploitable": true,
                "confidence": 0.9
            }),
            "requested-fingerprint",
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "verification output fingerprint mismatch: requested `requested-fingerprint`, received `hallucinated-fingerprint`"
        );
    }

    #[test]
    fn uses_requested_fingerprint_when_model_omits_identity() {
        let result = normalize_verification_result(
            json!({
                "exploitable": true,
                "confidence": 0.9
            }),
            "requested-fingerprint",
        )
        .unwrap();

        assert_eq!(result["fingerprint"], "requested-fingerprint");
    }

    #[test]
    fn rejects_present_empty_or_whitespace_fingerprint() {
        for fingerprint in ["", "   "] {
            let error = normalize_verification_result(
                json!({
                    "fingerprint": fingerprint,
                    "exploitable": true,
                    "confidence": 0.9
                }),
                "requested-fingerprint",
            )
            .unwrap_err();

            assert_eq!(
                error.to_string(),
                "verification output fingerprint must be a non-empty string"
            );
        }
    }

    #[test]
    fn rejects_present_non_string_fingerprint_without_echoing_value() {
        for fingerprint in [Value::Null, json!(42)] {
            let error = normalize_verification_result(
                json!({
                    "fingerprint": fingerprint,
                    "exploitable": true,
                    "confidence": 0.9
                }),
                "requested-fingerprint",
            )
            .unwrap_err()
            .to_string();

            assert!(error
                .starts_with("verification output fingerprint must be a non-empty string, got "));
            assert!(!error.contains("42"));
        }
    }

    #[test]
    fn accepts_model_fingerprint_matching_requested_finding() {
        let result = normalize_verification_result(
            json!({
                "fingerprint": "requested-fingerprint",
                "exploitable": true,
                "confidence": 0.9
            }),
            "requested-fingerprint",
        )
        .unwrap();

        assert_eq!(result["fingerprint"], "requested-fingerprint");
    }

    #[test]
    fn rejects_non_object_verification_output() {
        let err = normalize_verification_result(json!(["nope"]), "fp")
            .unwrap_err()
            .to_string();

        assert!(err.contains("expected a JSON object"));
    }

    #[test]
    fn rejects_missing_or_mistyped_exploitable_field() {
        let missing = normalize_verification_result(json!({"confidence": 0.4}), "fp")
            .unwrap_err()
            .to_string();
        assert!(missing.contains("missing required boolean"));

        let string_value =
            normalize_verification_result(json!({"exploitable": "yes", "confidence": 0.9}), "fp")
                .unwrap_err()
                .to_string();
        assert!(string_value.contains("must be boolean"));
        assert!(string_value.contains("string"));
    }

    #[test]
    fn rejects_missing_or_mistyped_confidence_field() {
        let missing = normalize_verification_result(json!({"exploitable": true}), "fp")
            .unwrap_err()
            .to_string();
        assert!(missing.contains("missing required number"));

        let string_value =
            normalize_verification_result(json!({"exploitable": true, "confidence": "high"}), "fp")
                .unwrap_err()
                .to_string();
        assert!(string_value.contains("must be number"));
        assert!(string_value.contains("string"));
    }

    #[test]
    fn builds_prompt_with_template_and_claim() {
        let finding = sql_injection_finding();

        let prompt = build_verify_prompt(&finding, Some("Custom verify")).unwrap();

        assert!(prompt.starts_with("Custom verify"));
        assert!(prompt.contains("SQL injection"));
    }

    #[test]
    fn prompt_withholds_triage_reasoning_from_the_verifier() {
        let mut finding = sql_injection_finding();
        finding.triage = Some(TriageOutcome {
            rationale: "discovery agent says definitely exploitable".to_string(),
            ..Default::default()
        });

        let prompt = build_verify_prompt(&finding, None).unwrap();

        // The verifier sees the claim (so it knows what to check)...
        assert!(prompt.contains("SQL injection"));
        // ...but never the discovery/triage agent's argument for it.
        assert!(!prompt.contains("discovery agent says definitely exploitable"));
        assert!(!prompt.contains("\"triage\""));
    }

    #[test]
    fn default_prompt_is_adversarial() {
        let prompt = build_verify_prompt(&sql_injection_finding(), None).unwrap();

        assert!(prompt.contains("false positive"));
        assert!(prompt.contains("CANNOT be exploited"));
    }

    fn sql_injection_finding() -> Finding {
        Finding::new_tool(
            "semgrep",
            "demo.rule",
            "src/db.rs",
            7,
            None,
            Severity::High,
            "SQL injection",
        )
    }
}
