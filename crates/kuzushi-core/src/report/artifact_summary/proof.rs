use crate::findings::is_runtime_proof_state;
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn proof_summary(value: &Value) -> Option<String> {
    let proof = proof_snapshot(value);
    static_proof_summary(proof).or_else(|| verification_proof_summary(proof))
}

fn proof_snapshot(value: &Value) -> &Value {
    value
        .get("proof")
        .or_else(|| value.get("proofs"))
        .or_else(|| value.get("verification"))
        .or_else(|| value.pointer("/data/proof"))
        .or_else(|| value.pointer("/data/proofs"))
        .or_else(|| value.pointer("/data/verification"))
        .unwrap_or(value)
}

fn static_proof_summary(value: &Value) -> Option<String> {
    let source = value.get("source").and_then(Value::as_str)?;
    let counts = value_at(value, &["countsByState", "counts_by_state"])?.as_object()?;
    let mut parts = vec![source.to_string()];
    parts.extend(proof_kind_segment(value));
    if let Some(proof_level) = value_at(value, &["proofLevel", "proof_level"]) {
        parts.push(format!("proofLevel={}", proof_level_summary(proof_level)));
    }
    if let Some(runtime) = runtime_verification_summary(value, counts) {
        parts.push(format!("runtimeVerification={runtime}"));
    }
    parts.extend(proof_findings_segment(value));
    parts.extend(proof_finding_unique_segment(
        value,
        "tools",
        &["tool"],
    ));
    parts.extend(proof_finding_unique_segment(
        value,
        "rules",
        &["ruleId", "rule_id"],
    ));
    parts.extend(proof_finding_unique_segment(
        value,
        "files",
        &["filePath", "file_path"],
    ));
    parts.push(format!("states {}", proof_state_summary(counts)?));
    Some(parts.join("; "))
}

fn runtime_verification_summary(
    value: &Value,
    counts: &serde_json::Map<String, Value>,
) -> Option<bool> {
    value_at(value, &["runtimeVerification", "runtime_verification"])
        .and_then(Value::as_bool)
        .or_else(|| proof_counts_include_runtime_state(counts).then_some(true))
}

fn proof_counts_include_runtime_state(counts: &serde_json::Map<String, Value>) -> bool {
    counts
        .keys()
        .any(|state| state_count_is_positive(counts, state) && is_runtime_proof_state(state))
}

fn state_count_is_positive(counts: &serde_json::Map<String, Value>, state: &str) -> bool {
    counts
        .get(state)
        .and_then(Value::as_u64)
        .is_some_and(|count| count > 0)
}

fn proof_state_summary(counts: &serde_json::Map<String, Value>) -> Option<String> {
    let mut states = counts.keys().collect::<Vec<_>>();
    states.sort();
    let summary = states
        .into_iter()
        .filter_map(|state| proof_state_segment(state, counts.get(state)))
        .collect::<Vec<_>>()
        .join(", ");
    (!summary.is_empty()).then_some(summary)
}

fn proof_state_segment(state: &str, value: Option<&Value>) -> Option<String> {
    Some(format!("{state}={}", value?.as_u64()?))
}

fn proof_findings_segment(value: &Value) -> Option<String> {
    value
        .get("findings")
        .and_then(Value::as_array)
        .map(|findings| format!("findings={}", findings.len()))
}

fn proof_finding_unique_segment(value: &Value, label: &str, keys: &[&str]) -> Option<String> {
    let findings = value.get("findings").and_then(Value::as_array)?;
    let mut counts = std::collections::BTreeMap::new();
    for field in findings.iter().filter_map(|finding| string_at(finding, keys)) {
        *counts.entry(field.to_string()).or_insert(0) += 1;
    }
    let summary = counts
        .into_iter()
        .map(|(name, count)| format!("{name}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    (!summary.is_empty()).then(|| format!("{label} {summary}"))
}

fn verification_proof_summary(value: &Value) -> Option<String> {
    let proof_level = value_at(value, &["proofLevel", "proof_level"])?;
    let verdict = value_at(value, &["proofVerdict", "proof_verdict"]).and_then(Value::as_str)?;
    let mut parts = proof_kind_segment(value).into_iter().collect::<Vec<_>>();
    parts.extend([
        format!("proofLevel={}", proof_level_summary(proof_level)),
        format!("verdict={verdict}"),
    ]);
    parts.extend(verified_segment(value));
    parts.extend(result_count_segment(value));
    parts.extend(result_verdict_segment(value));
    parts.extend(result_finding_segment(value));
    Some(parts.join(", "))
}

fn proof_kind_segment(value: &Value) -> Option<String> {
    value
        .get("kind")
        .and_then(Value::as_str)
        .filter(|kind| !kind.trim().is_empty())
        .map(|kind| format!("kind={kind}"))
}

fn proof_level_summary(value: &Value) -> String {
    value
        .as_u64()
        .map(|level| level.to_string())
        .or_else(|| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn value_at<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().filter_map(|key| value.get(*key)).next()
}

fn string_at<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .filter_map(|key| value.get(*key))
        .find_map(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn verified_segment(value: &Value) -> Option<String> {
    value_at(value, &["verified", "verifiedCount", "verified_count"])
        .and_then(Value::as_u64)
        .map(|verified| format!("verified={verified}"))
}

fn result_count_segment(value: &Value) -> Option<String> {
    verification_results(value).map(|results| format!("results={}", results.len()))
}

fn result_verdict_segment(value: &Value) -> Option<String> {
    let mut counts = BTreeMap::new();
    for verdict in verification_results(value)?
        .iter()
        .filter_map(|result| string_at(result, &["verdict", "proofVerdict", "proof_verdict"]))
    {
        *counts.entry(verdict.to_string()).or_insert(0) += 1;
    }
    count_map_segment("result verdicts", counts)
}

fn result_finding_segment(value: &Value) -> Option<String> {
    let count = verification_results(value)?
        .iter()
        .filter_map(|result| string_at(result, &["findingId", "finding_id", "fingerprint"]))
        .count();
    (count > 0).then(|| format!("result findings={count}"))
}

fn verification_results(value: &Value) -> Option<&Vec<Value>> {
    value_at(value, &["results", "verificationResults", "verification_results"])
        .and_then(Value::as_array)
}

fn count_map_segment(label: &str, counts: BTreeMap<String, usize>) -> Option<String> {
    let summary = counts
        .into_iter()
        .map(|(name, count)| format!("{name}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    (!summary.is_empty()).then(|| format!("{label} {summary}"))
}
