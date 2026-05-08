use super::prelude::*;
use super::*;

pub(in crate::modules) fn insert_verification_row_id(
    obj: &mut Map<String, Value>,
    persisted_id: Option<i64>,
) {
    if let Some(id) = persisted_id {
        obj.insert("verificationRowId".to_string(), json!(id));
    }
}

pub(in crate::modules) fn build_verify_prompt(
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

pub(in crate::modules) fn normalize_verification_result(
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
