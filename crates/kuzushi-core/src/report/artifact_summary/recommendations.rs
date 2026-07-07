use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn recommendation_summary(value: &Value) -> Option<String> {
    let report = recommendation_report(value);
    let recommendations = recommendation_items(report)?;
    if recommendations.is_empty() {
        return Some("0 recommendation(s)".to_string());
    }
    Some(recommendation_summary_parts(report, recommendations).join(", "))
}

fn recommendation_summary_parts(value: &Value, recommendations: &[Value]) -> Vec<String> {
    let mut parts = vec![format!("{} recommendation(s)", recommendations.len())];
    parts.extend(envelope_count_segments(value));
    parts.extend(tool_count_segments(value));
    parts.extend(priority_segment(recommendations));
    parts.extend(runtime_required_segment(recommendations));
    parts.extend(reason_segment(recommendations));
    parts.extend(next_input_segment(recommendations));
    parts.extend(recommendation_signal_segment(
        recommendations,
        "attack-surface risk tiers:",
    ));
    parts.extend(recommendation_signal_segment(
        recommendations,
        "attack-surface kinds:",
    ));
    parts.extend(recommendation_signal_segment(recommendations, "frameworks:"));
    parts.extend(recommended_tool_segment(recommendations));
    parts
}

fn envelope_count_segments(value: &Value) -> Vec<String> {
    ["warnings", "errors"]
        .into_iter()
        .filter_map(|field| array_count_segment(value, field))
        .collect()
}

fn array_count_segment(value: &Value, field: &str) -> Option<String> {
    let count = value.get(field).and_then(Value::as_array)?.len();
    (count > 0).then(|| format!("{field}={count}"))
}

fn tool_count_segments(value: &Value) -> Vec<String> {
    [
        ("available tools", &["availableToolCount", "available_tool_count"][..]),
        (
            "recommended tools",
            &["recommendedToolCount", "recommended_tool_count"][..],
        ),
    ]
    .into_iter()
    .filter_map(|(label, keys)| tool_count_segment(value, label, keys))
    .chain(skipped_missing_tools_segment(value))
    .collect()
}

fn tool_count_segment(value: &Value, label: &str, keys: &[&str]) -> Option<String> {
    value_at(value, keys)
        .or_else(|| nested_value_at(value, "capabilities", keys))
        .and_then(Value::as_u64)
        .map(|count| format!("{label}={count}"))
}

fn skipped_missing_tools_segment(value: &Value) -> Option<String> {
    let count = value_at(value, &["skippedMissingTools", "skipped_missing_tools"])
        .or_else(|| {
            nested_value_at(
                value,
                "capabilities",
                &["skippedMissingTools", "skipped_missing_tools"],
            )
        })
        .and_then(Value::as_array)?
        .len();
    (count > 0).then(|| format!("skipped missing={count}"))
}

fn recommendation_items(value: &Value) -> Option<&[Value]> {
    value
        .get("recommendations")
        .or_else(|| value.pointer("/data/recommendations"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
}

fn recommendation_report(value: &Value) -> &Value {
    value
        .get("recommendationReport")
        .or_else(|| value.pointer("/data/recommendationReport"))
        .or_else(|| recommendation_report_data(value))
        .unwrap_or(value)
}

fn recommendation_report_data(value: &Value) -> Option<&Value> {
    let data = value.get("data")?;
    has_recommendations(data).then_some(data)
}

fn has_recommendations(value: &Value) -> bool {
    value
        .get("recommendations")
        .and_then(Value::as_array)
        .is_some()
}

fn priority_segment(recommendations: &[Value]) -> Option<String> {
    recommendation_field_summary(recommendations, "priority")
        .map(|priorities| format!("priority {priorities}"))
}

fn runtime_required_segment(recommendations: &[Value]) -> Option<String> {
    let count = recommendations
        .iter()
        .filter(|recommendation| bool_field(recommendation, &["requiresRuntime", "requires_runtime"]))
        .count();
    (count > 0).then(|| format!("runtime required={count}"))
}

fn reason_segment(recommendations: &[Value]) -> Option<String> {
    let count = recommendations
        .iter()
        .filter(|recommendation| string_field(recommendation, "reason").is_some())
        .count();
    (count > 0).then(|| format!("reasons={count}"))
}

fn next_input_segment(recommendations: &[Value]) -> Option<String> {
    let count = recommendations
        .iter()
        .filter(|recommendation| object_field(recommendation, &["nextInput", "next_input"]))
        .count();
    (count > 0).then(|| format!("next inputs={count}"))
}

fn recommended_tool_segment(recommendations: &[Value]) -> Option<String> {
    let tools = recommendations
        .iter()
        .filter_map(recommendation_tool_label)
        .take(3)
        .collect::<Vec<_>>();
    (!tools.is_empty()).then(|| format!("tools {}", tools.join(", ")))
}

fn recommendation_tool_label(recommendation: &Value) -> Option<&str> {
    ["tool", "moduleId", "module_id"]
        .into_iter()
        .find_map(|key| string_field(recommendation, key))
}

fn recommendation_signal_segment(recommendations: &[Value], prefix: &str) -> Option<String> {
    recommendations
        .iter()
        .filter_map(|recommendation| matching_signal(recommendation, prefix))
        .next()
        .map(str::to_string)
}

fn matching_signal<'a>(recommendation: &'a Value, prefix: &str) -> Option<&'a str> {
    recommendation
        .get("signals")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(Value::as_str)
        .find(|signal| signal.starts_with(prefix))
}

fn recommendation_field_summary(recommendations: &[Value], key: &str) -> Option<String> {
    let mut counts = BTreeMap::new();
    for recommendation in recommendations {
        if let Some(value) = string_field(recommendation, key) {
            *counts.entry(value.to_string()).or_insert(0) += 1;
        }
    }
    count_segments(&counts)
}

fn count_segments(counts: &BTreeMap<String, usize>) -> Option<String> {
    let mut keys = counts.keys().collect::<Vec<_>>();
    keys.sort_by(|left, right| {
        priority_order(left)
            .cmp(&priority_order(right))
            .then_with(|| left.cmp(right))
    });
    let summary = keys
        .into_iter()
        .filter_map(|key| counts.get(key).map(|count| format!("{key}={count}")))
        .collect::<Vec<_>>()
        .join(", ");
    (!summary.is_empty()).then_some(summary)
}

fn priority_order(priority: &str) -> usize {
    match priority {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    }
}

fn string_field<'a>(object: &'a Value, key: &str) -> Option<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn bool_field(object: &Value, keys: &[&str]) -> bool {
    keys.iter()
        .filter_map(|key| object.get(*key))
        .find_map(Value::as_bool)
        .unwrap_or(false)
}

fn object_field(object: &Value, keys: &[&str]) -> bool {
    keys.iter()
        .filter_map(|key| object.get(*key))
        .find_map(Value::as_object)
        .is_some_and(|object| !object.is_empty())
}

fn value_at<'a>(object: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

fn nested_value_at<'a>(object: &'a Value, parent: &str, keys: &[&str]) -> Option<&'a Value> {
    value_at(object.get(parent)?, keys)
}
