use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn context_summary(value: &Value) -> Option<String> {
    let snapshot = context_snapshot(value);
    if !looks_like_context_snapshot(snapshot) {
        return None;
    }
    let mut parts = vec![format!("{} file(s)", context_file_count(snapshot))];
    parts.extend(context_truncated_segment(snapshot));
    parts.extend(pattern_match_segment(snapshot));
    parts.extend(repo_context_list_segment(snapshot, "languages", "languages"));
    parts.extend(repo_context_list_segment(snapshot, "frameworks", "frameworks"));
    parts.extend(app_model_segments(snapshot));
    parts.extend(route_field_segment(snapshot, "methods", "method"));
    parts.extend(route_field_segment(snapshot, "route frameworks", "framework"));
    Some(parts.join(", "))
}

fn context_snapshot(value: &Value) -> &Value {
    value
        .get("context")
        .or_else(|| value.get("contextSnapshot"))
        .or_else(|| value.pointer("/data/context"))
        .or_else(|| value.pointer("/data/snapshot"))
        .unwrap_or(value)
}

fn looks_like_context_snapshot(value: &Value) -> bool {
    repo_context(value).is_some()
        || value.get("fileIndex").is_some()
        || app_model(value).is_some()
}

fn context_file_count(value: &Value) -> u64 {
    value
        .get("filesIndexed")
        .or_else(|| value.pointer("/fileIndex/totalFiles"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

fn context_truncated_segment(value: &Value) -> Option<String> {
    let truncated = value
        .pointer("/fileIndex/truncated")
        .and_then(Value::as_bool)?;
    truncated.then(|| "file index truncated".to_string())
}

fn pattern_match_segment(value: &Value) -> Option<String> {
    let matches = value
        .pointer("/fileIndex/patternMatches")?
        .as_object()?;
    let total = matches.values().filter_map(pattern_match_count).sum::<u64>();
    (total > 0).then(|| format!("pattern matches {total}"))
}

fn pattern_match_count(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_array().map(|items| items.len() as u64))
}

fn repo_context_list_segment(value: &Value, key: &str, label: &str) -> Option<String> {
    let items = repo_context(value)?
        .get(key)
        .and_then(Value::as_array)?
        .iter()
        .filter_map(Value::as_str)
        .filter(|item| !item.trim().is_empty())
        .take(6)
        .collect::<Vec<_>>();
    (!items.is_empty()).then(|| format!("{label} {}", items.join(", ")))
}

fn repo_context(value: &Value) -> Option<&Value> {
    value.get("repoContext")
}

fn app_model_segments(value: &Value) -> Vec<String> {
    let app_model = app_model(value);
    [
        ("routes", "route(s)"),
        ("outboundClients", "outbound client(s)"),
        ("serviceBoundaries", "service boundary(ies)"),
        ("dataStores", "data store(s)"),
        ("backgroundJobs", "background job(s)"),
    ]
    .into_iter()
    .filter_map(|(key, label)| app_model_count_segment(app_model, key, label))
    .collect()
}

fn app_model(value: &Value) -> Option<&Value> {
    value.get("appModel")
}

fn app_model_count_segment(app_model: Option<&Value>, key: &str, label: &str) -> Option<String> {
    let count = app_model?.get(key).and_then(Value::as_array)?.len();
    (count > 0).then(|| format!("{count} {label}"))
}

fn route_field_segment(value: &Value, label: &str, key: &str) -> Option<String> {
    let mut counts = BTreeMap::new();
    for route in app_model(value)?
        .get("routes")?
        .as_array()?
        .iter()
        .filter_map(|route| string_field(route, key))
    {
        *counts.entry(route.to_string()).or_insert(0) += 1;
    }
    count_segment(label, counts)
}

fn count_segment(label: &str, counts: BTreeMap<String, usize>) -> Option<String> {
    let summary = counts
        .into_iter()
        .map(|(name, count)| format!("{name}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    (!summary.is_empty()).then(|| format!("{label} {summary}"))
}

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}
