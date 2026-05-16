use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn summarize_text_artifact(body: &str) -> String {
    format!("{} line(s)", body.lines().count())
}

pub(super) fn summarize_json_artifact(value: &Value) -> String {
    if let Some(summary) = text_summary(value) {
        return summary;
    }
    match value {
        Value::Array(items) => format!("{} record(s)", items.len()),
        Value::Object(object) => format!("{} top-level field(s)", object.len()),
        _ => "present".to_string(),
    }
}

fn text_summary(value: &Value) -> Option<String> {
    value
        .get("summary")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| threat_model_summary(value))
        .or_else(|| attack_surface_summary(value))
}

fn threat_model_summary(value: &Value) -> Option<String> {
    let document = value.get("document").unwrap_or(value);
    let threats = array_len(document.get("threats"));
    let dfd = document.get("dfd");
    let nodes = array_len(dfd.and_then(|value| value.get("nodes")));
    let flows = array_len(dfd.and_then(|value| value.get("flows")));
    let boundaries = array_len(dfd.and_then(|value| value.get("trustBoundaries")));
    if threats.is_none() && nodes.is_none() {
        return None;
    }
    let mut parts = methodology_segment(document).into_iter().collect::<Vec<_>>();
    parts.push(format!("{} threat(s)", threats.unwrap_or_default()));
    parts.extend(dfd_segments(nodes, flows, boundaries));
    parts.extend(related_cwe_segment(document));
    Some(parts.join(", "))
}

fn methodology_segment(document: &Value) -> Option<String> {
    document
        .get("methodology")
        .and_then(Value::as_str)
        .map(|methodology| format!("methodology {methodology}"))
}

fn dfd_segments(
    nodes: Option<usize>,
    flows: Option<usize>,
    boundaries: Option<usize>,
) -> Vec<String> {
    vec![
        format!("DFD nodes={}", nodes.unwrap_or_default()),
        format!("flows={}", flows.unwrap_or_default()),
        format!("boundaries={}", boundaries.unwrap_or_default()),
    ]
}

fn related_cwe_segment(document: &Value) -> Option<String> {
    let counts = related_cwe_counts(document.get("threats"));
    if counts.is_empty() {
        return None;
    }
    Some(format!("CWEs {}", cwe_count_segments(&counts).join(", ")))
}

fn related_cwe_counts(value: Option<&Value>) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    let Some(threats) = value.and_then(Value::as_array) else {
        return counts;
    };
    for threat in threats {
        collect_related_cwes(threat.get("relatedCwe"), &mut counts);
    }
    counts
}

fn collect_related_cwes(value: Option<&Value>, counts: &mut BTreeMap<String, usize>) {
    let Some(cwes) = value.and_then(Value::as_array) else {
        return;
    };
    for cwe in cwes.iter().filter_map(Value::as_str).filter(non_empty) {
        *counts.entry(cwe.to_string()).or_insert(0) += 1;
    }
}

fn non_empty(value: &&str) -> bool {
    !value.trim().is_empty()
}

fn cwe_count_segments(counts: &BTreeMap<String, usize>) -> Vec<String> {
    counts
        .iter()
        .take(8)
        .map(|(cwe, count)| format!("{cwe}={count}"))
        .collect()
}

fn array_len(value: Option<&Value>) -> Option<usize> {
    value.and_then(Value::as_array).map(Vec::len)
}

fn attack_surface_summary(value: &Value) -> Option<String> {
    let summary = value.get("summary")?.as_object()?;
    let total = summary.get("surfaceCount")?.as_u64()?;
    let high = summary.get("highRisk").and_then(Value::as_u64).unwrap_or(0);
    let mut parts = vec![format!("{total} surface(s)"), format!("{high} high risk")];
    if let Some(max) = summary.get("maxRiskScore").and_then(Value::as_u64) {
        parts.push(format!("max {max}"));
    }
    if let Some(tiers) = risk_tier_summary(summary.get("byRiskTier")) {
        parts.push(format!("tiers {tiers}"));
    }
    Some(parts.join(", "))
}

fn risk_tier_summary(value: Option<&Value>) -> Option<String> {
    let object = value?.as_object()?;
    let mut tiers = object.keys().collect::<Vec<_>>();
    tiers.sort_by(|left, right| {
        tier_rank(left)
            .cmp(&tier_rank(right))
            .then_with(|| left.cmp(right))
    });
    let summary = tiers
        .into_iter()
        .filter_map(|tier| tier_count_segment(tier, object.get(tier)))
        .collect::<Vec<_>>()
        .join(", ");
    (!summary.is_empty()).then_some(summary)
}

fn tier_count_segment(tier: &str, count: Option<&Value>) -> Option<String> {
    let count = count.and_then(Value::as_u64).filter(|count| *count > 0)?;
    Some(format!("{tier}={count}"))
}

fn tier_rank(tier: &str) -> usize {
    match tier {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}
