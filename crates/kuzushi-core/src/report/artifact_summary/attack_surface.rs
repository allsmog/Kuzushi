use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn attack_surface_summary(value: &Value) -> Option<String> {
    let summary = summary_object(value)?;
    let surfaces = surface_array(value);
    let total = surface_total(summary).or_else(|| surface_count(surfaces))?;
    let high = summary_u64(summary, "highRisk")
        .or_else(|| high_risk_surface_count(surfaces))
        .unwrap_or(0);
    Some(attack_surface_segments(summary, surfaces, total, high).join(", "))
}

fn summary_object(value: &Value) -> Option<&serde_json::Map<String, Value>> {
    value
        .get("summary")
        .and_then(Value::as_object)
        .or_else(|| value.as_object())
}

fn surface_total(summary: &serde_json::Map<String, Value>) -> Option<u64> {
    summary_u64(summary, "surfaceCount").or_else(|| summary_u64(summary, "total"))
}

fn summary_u64(summary: &serde_json::Map<String, Value>, key: &str) -> Option<u64> {
    summary_value(summary, key).and_then(Value::as_u64)
}

fn summary_value<'a>(summary: &'a serde_json::Map<String, Value>, key: &str) -> Option<&'a Value> {
    summary.get(key)
}

fn attack_surface_segments(
    summary: &serde_json::Map<String, Value>,
    surfaces: Option<&Value>,
    total: u64,
    high: u64,
) -> Vec<String> {
    let mut parts = vec![format!("{total} surface(s)"), format!("{high} high risk")];
    parts.extend(max_risk_segment(summary).or_else(|| max_surface_risk_segment(surfaces)));
    parts.extend(named_segment(
        "tiers",
        risk_tier_summary(summary_value(summary, "byRiskTier"))
            .or_else(|| surface_risk_tier_summary(surfaces)),
    ));
    parts.extend(named_segment(
        "kinds",
        attack_surface_kind_summary(summary_value(summary, "byKind"), surfaces),
    ));
    parts.extend(named_segment("frameworks", attack_surface_framework_summary(surfaces)));
    parts.extend(named_segment("languages", attack_surface_language_summary(surfaces)));
    parts.extend(named_segment("methods", attack_surface_method_summary(surfaces)));
    parts.extend(named_segment("boundaries", attack_surface_boundary_summary(surfaces)));
    parts
}

fn max_risk_segment(summary: &serde_json::Map<String, Value>) -> Option<String> {
    summary_u64(summary, "maxRiskScore").map(|max| format!("max {max}"))
}

fn max_surface_risk_segment(value: Option<&Value>) -> Option<String> {
    surface_risk_scores(value)
        .into_iter()
        .max()
        .map(|max| format!("max {max}"))
}

fn named_segment(name: &str, value: Option<String>) -> Option<String> {
    value.map(|value| format!("{name} {value}"))
}

fn attack_surface_kind_summary(
    summary_kinds: Option<&Value>,
    surfaces: Option<&Value>,
) -> Option<String> {
    kind_count_segments(&summary_kind_counts(summary_kinds).or_else(|| surface_kind_counts(surfaces))?)
}

fn summary_kind_counts(value: Option<&Value>) -> Option<BTreeMap<String, usize>> {
    let object = value?.as_object()?;
    let counts = object
        .iter()
        .filter_map(|(kind, count)| count.as_u64().map(|count| (kind.clone(), count as usize)))
        .filter(|(_, count)| *count > 0)
        .collect::<BTreeMap<_, _>>();
    (!counts.is_empty()).then_some(counts)
}

fn surface_kind_counts(value: Option<&Value>) -> Option<BTreeMap<String, usize>> {
    surface_field_counts(value, "kind")
}

fn attack_surface_framework_summary(value: Option<&Value>) -> Option<String> {
    framework_count_segments(&surface_field_counts(value, "framework")?)
}

fn attack_surface_language_summary(value: Option<&Value>) -> Option<String> {
    language_count_segments(&surface_field_counts(value, "language")?)
}

fn attack_surface_method_summary(value: Option<&Value>) -> Option<String> {
    method_count_segments(&surface_field_counts(value, "method")?)
}

fn attack_surface_boundary_summary(value: Option<&Value>) -> Option<String> {
    boundary_count_segments(&surface_field_counts(value, "boundary")?)
}

fn surface_array(value: &Value) -> Option<&Value> {
    value.get("surfaces")
}

fn surface_count(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_array).map(|surfaces| surfaces.len() as u64)
}

fn high_risk_surface_count(value: Option<&Value>) -> Option<u64> {
    let count = surface_risk_tiers(value)
        .into_iter()
        .filter(|tier| matches!(*tier, "critical" | "high"))
        .count();
    (count > 0).then_some(count as u64)
}

fn surface_risk_tier_summary(value: Option<&Value>) -> Option<String> {
    let mut counts = BTreeMap::new();
    for tier in surface_risk_tiers(value) {
        *counts.entry(tier.to_string()).or_insert(0) += 1;
    }
    risk_tier_count_segments(&counts)
}

fn surface_risk_tiers(value: Option<&Value>) -> Vec<&str> {
    surface_values(value)
        .into_iter()
        .filter_map(surface_risk_tier)
        .collect()
}

fn surface_risk_scores(value: Option<&Value>) -> Vec<u64> {
    surface_values(value)
        .into_iter()
        .filter_map(surface_risk_score)
        .collect()
}

fn surface_values(value: Option<&Value>) -> Vec<&Value> {
    value
        .and_then(Value::as_array)
        .map(|surfaces| surfaces.iter().collect())
        .unwrap_or_default()
}

fn surface_risk_tier(surface: &Value) -> Option<&str> {
    surface
        .pointer("/risk/tier")
        .or_else(|| surface.get("tier"))
        .and_then(Value::as_str)
        .filter(non_empty)
}

fn surface_risk_score(surface: &Value) -> Option<u64> {
    surface
        .pointer("/risk/score")
        .or_else(|| surface.get("score"))
        .and_then(Value::as_u64)
}

fn surface_field_counts(value: Option<&Value>, field: &str) -> Option<BTreeMap<String, usize>> {
    let surfaces = value.and_then(Value::as_array)?;
    let mut counts = BTreeMap::new();
    for surface in surfaces {
        if let Some(value) = surface.get(field).and_then(Value::as_str).filter(non_empty) {
            *counts.entry(value.to_string()).or_insert(0) += 1;
        }
    }
    (!counts.is_empty()).then_some(counts)
}

fn kind_count_segments(counts: &BTreeMap<String, usize>) -> Option<String> {
    count_segments(counts, alphabetical_order, 8)
}

fn framework_count_segments(counts: &BTreeMap<String, usize>) -> Option<String> {
    count_segments(counts, alphabetical_order, 6)
}

fn language_count_segments(counts: &BTreeMap<String, usize>) -> Option<String> {
    count_segments(counts, alphabetical_order, 6)
}

fn method_count_segments(counts: &BTreeMap<String, usize>) -> Option<String> {
    count_segments(counts, alphabetical_order, 6)
}

fn boundary_count_segments(counts: &BTreeMap<String, usize>) -> Option<String> {
    count_segments(counts, alphabetical_order, 6)
}

fn risk_tier_summary(value: Option<&Value>) -> Option<String> {
    let object = value?.as_object()?;
    let counts = object
        .iter()
        .filter_map(|(tier, count)| count.as_u64().map(|count| (tier.clone(), count as usize)))
        .collect::<BTreeMap<_, _>>();
    risk_tier_count_segments(&counts)
}

fn risk_tier_count_segments(counts: &BTreeMap<String, usize>) -> Option<String> {
    let mut tiers = counts.keys().collect::<Vec<_>>();
    tiers.sort_by(|left, right| {
        tier_rank(left)
            .cmp(&tier_rank(right))
            .then_with(|| left.cmp(right))
    });
    let summary = tiers
        .into_iter()
        .filter_map(|tier| tier_count_segment(tier, counts.get(tier)))
        .collect::<Vec<_>>()
        .join(", ");
    (!summary.is_empty()).then_some(summary)
}

fn tier_count_segment(tier: &str, count: Option<&usize>) -> Option<String> {
    let count = count.filter(|count| **count > 0)?;
    Some(format!("{tier}={count}"))
}

fn count_segments(
    counts: &BTreeMap<String, usize>,
    order: fn(&str) -> usize,
    limit: usize,
) -> Option<String> {
    let mut keys = counts.keys().collect::<Vec<_>>();
    keys.sort_by(|left, right| order(left).cmp(&order(right)).then_with(|| left.cmp(right)));
    let summary = keys
        .into_iter()
        .take(limit)
        .filter_map(|key| counts.get(key).map(|count| format!("{key}={count}")))
        .collect::<Vec<_>>()
        .join(", ");
    (!summary.is_empty()).then_some(summary)
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

fn alphabetical_order(_: &str) -> usize {
    0
}

fn non_empty(value: &&str) -> bool {
    !value.trim().is_empty()
}
