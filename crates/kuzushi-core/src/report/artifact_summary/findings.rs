use super::severity::{canonical_severity, severity_order};
use crate::findings::StaticProofState;
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn findings_summary(value: &Value) -> Option<String> {
    let findings = finding_items(value)?;
    if findings.is_empty() {
        return Some("0 finding(s)".to_string());
    }
    Some(finding_segments(findings).join(", "))
}

fn finding_items(value: &Value) -> Option<&[Value]> {
    value
        .as_array()
        .or_else(|| value.get("coreFindings").and_then(Value::as_array))
        .or_else(|| value.get("findings").and_then(Value::as_array))
        .or_else(|| value.pointer("/data/coreFindings").and_then(Value::as_array))
        .or_else(|| value.pointer("/data/findings").and_then(Value::as_array))
        .map(Vec::as_slice)
}

fn finding_segments(findings: &[Value]) -> Vec<String> {
    let mut parts = vec![format!("{} finding(s)", findings.len())];
    parts.extend(named_segment(
        "severity",
        finding_field_summary(findings, "severity", severity_order),
    ));
    parts.extend(named_segment(
        "proof",
        finding_field_summary(findings, "staticProofState", alphabetical_order),
    ));
    parts.extend(named_segment("confidence", confidence_summary(findings)));
    parts.extend(named_segment("CWEs", cwe_summary(findings)));
    parts.extend(named_segment("root causes", root_cause_summary(findings)));
    parts.extend(named_segment("tools", finding_unique_summary(findings, "tool")));
    parts.extend(named_segment("rules", finding_unique_summary(findings, "ruleId")));
    parts.extend(named_segment("files", finding_unique_summary(findings, "filePath")));
    parts.extend(named_count("suppressed", findings, suppressed_count));
    parts.extend(named_count("snoozed", findings, snoozed_count));
    parts.extend(named_count("remediation", findings, remediation_count));
    parts.extend(named_count("references", findings, reference_count));
    parts
}

fn named_segment(name: &str, summary: Option<String>) -> Option<String> {
    summary.map(|summary| format!("{name} {summary}"))
}

fn named_count(name: &str, findings: &[Value], count: fn(&Value) -> usize) -> Option<String> {
    let total = findings.iter().map(count).sum::<usize>();
    (total > 0).then(|| format!("{name} {total}"))
}

fn finding_field_summary(
    findings: &[Value],
    key: &str,
    order: fn(&str) -> usize,
) -> Option<String> {
    let mut counts = BTreeMap::new();
    for finding in findings {
        if let Some(value) = finding_string_field(finding, key) {
            *counts.entry(summary_field_value(key, value)).or_insert(0) += 1;
        }
    }
    count_segments(&counts, order)
}

fn summary_field_value(key: &str, value: &str) -> String {
    match key {
        "severity" => canonical_severity(value),
        "staticProofState" => canonical_static_proof_state(value),
        _ => value.to_string(),
    }
}

fn canonical_static_proof_state(value: &str) -> String {
    StaticProofState::try_from(value)
        .map(StaticProofState::as_str)
        .unwrap_or(value)
        .to_string()
}

fn finding_string_field<'a>(finding: &'a Value, key: &str) -> Option<&'a str> {
    finding.get(key).and_then(string_value)
}

fn string_value(value: &Value) -> Option<&str> {
    value.as_str().filter(|value| !value.trim().is_empty())
}

fn confidence_summary(findings: &[Value]) -> Option<String> {
    let mut counts = BTreeMap::new();
    for finding in findings {
        if let Some(confidence) = confidence_bucket(finding.get("confidence")) {
            *counts.entry(confidence).or_insert(0) += 1;
        }
    }
    count_segments(&counts, confidence_order)
}

fn confidence_bucket(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(canonical_confidence)
        .or_else(|| value.and_then(Value::as_f64).map(numeric_confidence))
}

/// Qualitative root-cause grouping: how many distinct underlying problems
/// the findings represent, clustering by `(file, normalized CWE)` so multiple
/// call sites of one defect count once. Only emitted when clustering actually
/// collapses findings (root causes < findings) so it reads as a noise signal
/// — "12 finding(s), ... root causes 7" — and stays silent otherwise.
fn root_cause_summary(findings: &[Value]) -> Option<String> {
    let mut keys = std::collections::BTreeSet::new();
    for (index, finding) in findings.iter().enumerate() {
        keys.insert(finding_root_cause_key(finding, index));
    }
    let root_causes = keys.len();
    (root_causes < findings.len() && root_causes > 0).then(|| root_causes.to_string())
}

/// A finding clusters by `(file, CWE)` only when it has a file path; a
/// finding with no location is unidentifiable and counts as its own root
/// cause (a per-index sentinel) rather than collapsing with other fileless
/// findings on an empty key.
fn finding_root_cause_key(finding: &Value, index: usize) -> String {
    match finding_string_field(finding, "filePath") {
        Some(file) => {
            crate::findings::compute_root_cause_key(file, finding_cwes(finding).into_iter().next())
        }
        None => format!("#fileless-{index}"),
    }
}

fn cwe_summary(findings: &[Value]) -> Option<String> {
    let mut counts = BTreeMap::new();
    for cwe in findings.iter().flat_map(finding_cwes) {
        *counts.entry(cwe.to_string()).or_insert(0) += 1;
    }
    count_segments(&counts, alphabetical_order)
}

fn finding_unique_summary(findings: &[Value], key: &str) -> Option<String> {
    let mut counts = BTreeMap::new();
    for value in findings.iter().filter_map(|finding| finding_string_field(finding, key)) {
        *counts.entry(value.to_string()).or_insert(0) += 1;
    }
    count_segments(&counts, alphabetical_order)
}

fn finding_cwes(finding: &Value) -> Vec<&str> {
    match finding.get("cwe") {
        Some(Value::String(cwe)) if !cwe.trim().is_empty() => vec![cwe.as_str()],
        Some(Value::Array(cwes)) => cwes
            .iter()
            .filter_map(Value::as_str)
            .filter(|cwe| !cwe.trim().is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

fn suppressed_count(finding: &Value) -> usize {
    finding
        .get("suppressed")
        .and_then(Value::as_bool)
        .is_some_and(|suppressed| suppressed) as usize
}

fn snoozed_count(finding: &Value) -> usize {
    finding_string_field(finding, "snoozedUntil").is_some() as usize
}

fn remediation_count(finding: &Value) -> usize {
    finding_string_field(finding, "remediation").is_some() as usize
}

fn reference_count(finding: &Value) -> usize {
    finding
        .get("references")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

fn canonical_confidence(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "high" => "high".to_string(),
        "medium" => "medium".to_string(),
        "low" => "low".to_string(),
        "unknown" => "unknown".to_string(),
        other => other.to_string(),
    }
}

fn numeric_confidence(value: f64) -> String {
    match normalized_confidence(value) {
        value if value >= 0.8 => "high".to_string(),
        value if value >= 0.4 => "medium".to_string(),
        _ => "low".to_string(),
    }
}

fn normalized_confidence(value: f64) -> f64 {
    if value > 1.0 { value / 100.0 } else { value }
}

fn count_segments(
    counts: &BTreeMap<String, usize>,
    order: fn(&str) -> usize,
) -> Option<String> {
    let mut keys = counts.keys().collect::<Vec<_>>();
    keys.sort_by(|left, right| order(left).cmp(&order(right)).then_with(|| left.cmp(right)));
    let summary = keys
        .into_iter()
        .filter_map(|key| counts.get(key).map(|count| format!("{key}={count}")))
        .collect::<Vec<_>>()
        .join(", ");
    (!summary.is_empty()).then_some(summary)
}

fn alphabetical_order(_: &str) -> usize {
    0
}

fn confidence_order(confidence: &str) -> usize {
    match confidence {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        "unknown" => 3,
        _ => 4,
    }
}
