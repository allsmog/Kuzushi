use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

use crate::findings::{is_runtime_proof_state, StaticProofState};

const EXPLICIT_PROOF_POINTERS: &[&str] = &["/data/proof", "/proof"];

const FINDING_POINTERS: &[&str] = &["/data/coreFindings", "/data/findings", "/coreFindings", "/findings"];

pub(crate) fn proof_snapshot_value(output: &Value) -> Option<Value> {
    explicit_proof_snapshot(output)
        .or_else(|| static_proof_snapshot(output))
}

fn explicit_proof_snapshot(output: &Value) -> Option<Value> {
    value_at(output, EXPLICIT_PROOF_POINTERS).cloned()
}

fn static_proof_snapshot(output: &Value) -> Option<Value> {
    let findings = finding_values(output)?;
    let entries = findings.iter().filter_map(static_proof_entry).collect::<Vec<_>>();
    (!entries.is_empty()).then(|| static_proof_report(entries))
}

fn finding_values(output: &Value) -> Option<&Vec<Value>> {
    value_at(output, FINDING_POINTERS).and_then(Value::as_array)
}

fn static_proof_entry(finding: &Value) -> Option<Value> {
    let object = finding.as_object()?;
    let state = canonical_proof_state(string_field(object, "staticProofState")?);
    Some(json!({
        "fingerprint": string_field(object, "fingerprint"),
        "tool": string_field(object, "tool"),
        "ruleId": string_field(object, "ruleId"),
        "filePath": string_field(object, "filePath"),
        "startLine": object.get("startLine").cloned(),
        "staticProofState": state,
    }))
}

fn canonical_proof_state(raw: &str) -> String {
    StaticProofState::try_from(raw)
        .map(StaticProofState::as_str)
        .unwrap_or_else(|_| raw.trim())
        .to_string()
}

fn static_proof_report(entries: Vec<Value>) -> Value {
    let runtime_verification = has_runtime_proof_state(&entries);
    json!({
        "status": "completed",
        "summary": format!("{} proof state(s) recorded from normalized findings", entries.len()),
        "source": "normalized-findings",
        "proofLevel": proof_level(runtime_verification),
        "runtimeVerification": runtime_verification,
        "countsByState": counts_by_state(&entries),
        "findings": entries,
    })
}

fn proof_level(runtime_verification: bool) -> &'static str {
    if runtime_verification {
        "runtime-and-static"
    } else {
        "static-signal-only"
    }
}

fn has_runtime_proof_state(entries: &[Value]) -> bool {
    entries
        .iter()
        .filter_map(|entry| entry.get("staticProofState").and_then(Value::as_str))
        .any(is_runtime_proof_state)
}

fn counts_by_state(entries: &[Value]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for entry in entries {
        if let Some(state) = entry.get("staticProofState").and_then(Value::as_str) {
            *counts.entry(state.to_string()).or_default() += 1;
        }
    }
    counts
}

fn string_field<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

fn value_at<'a>(output: &'a Value, pointers: &[&str]) -> Option<&'a Value> {
    pointers
        .iter()
        .filter_map(|pointer| output.pointer(pointer))
        .find(|value| !value.is_null())
}
