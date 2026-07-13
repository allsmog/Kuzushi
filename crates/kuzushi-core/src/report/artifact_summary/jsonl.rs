use crate::run_artifacts::canonical_run_artifact_spec;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn jsonl_summary(file: &str, body: &str) -> Option<String> {
    if file == run_events_artifact_leaf() {
        return events_summary(body);
    }
    if file == run_trace_artifact_leaf() {
        return trace_summary(body);
    }
    None
}

fn run_events_artifact_leaf() -> &'static str {
    canonical_run_artifact_spec("events.jsonl")
        .expect("run events artifact must be in shared canonical spec")
        .leaf
}

fn run_trace_artifact_leaf() -> &'static str {
    canonical_run_artifact_spec("trace.jsonl")
        .expect("runtime trace artifact must be in shared canonical spec")
        .leaf
}

fn events_summary(body: &str) -> Option<String> {
    let lines = json_lines(body);
    if lines
        .values
        .iter()
        .any(|event| event.get("status").is_some())
    {
        let mut parts = vec![format!("{} event(s)", lines.values.len())];
        parts.extend(count_segment("kinds", string_counts(&lines.values, "kind")));
        parts.extend(count_segment("status", event_status_counts(&lines.values)));
        parts.extend(tool_segment(&lines.values));
        parts.extend(event_span_segment(&lines.values));
        parts.extend(artifact_count_segment(&lines.values));
        parts.extend(malformed_line_segment(&lines));
        return Some(parts.join(", "));
    }
    malformed_jsonl_summary(&lines)
}

fn trace_summary(body: &str) -> Option<String> {
    let lines = json_lines(body);
    if lines.values.iter().any(|step| trace_label(step).is_some()) {
        let mut parts = vec![format!("{} step(s)", lines.values.len())];
        parts.extend(count_segment("kinds", string_counts(&lines.values, "kind")));
        parts.extend(count_segment(
            "severity",
            string_counts(&lines.values, "severity"),
        ));
        parts.extend(trace_module_segment(&lines.values));
        parts.extend(trace_verb_segment(&lines.values));
        parts.extend(trace_child_step_segment(&lines.values));
        parts.extend(llm_call_segment(&lines.values));
        parts.extend(trace_latency_segment(&lines.values));
        parts.extend(trace_cost_segment(&lines.values));
        parts.extend(malformed_line_segment(&lines));
        return Some(parts.join(", "));
    }
    malformed_jsonl_summary(&lines)
}

struct JsonLines {
    values: Vec<Value>,
    malformed: usize,
}

fn json_lines(body: &str) -> JsonLines {
    let mut values = Vec::new();
    let mut malformed = 0;
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        match serde_json::from_str::<Value>(line) {
            Ok(value) if value.is_object() => values.push(value),
            Ok(_) => malformed += 1,
            Err(_) => malformed += 1,
        }
    }
    JsonLines { values, malformed }
}

fn malformed_line_segment(lines: &JsonLines) -> Option<String> {
    (lines.malformed > 0).then(|| format!("malformed line(s) {}", lines.malformed))
}

fn malformed_jsonl_summary(lines: &JsonLines) -> Option<String> {
    (lines.malformed > 0).then(|| format!("malformed JSONL line(s) {}", lines.malformed))
}

fn event_status_counts(events: &[Value]) -> BTreeMap<String, usize> {
    string_counts(events, "status")
}

fn string_counts(items: &[Value], key: &str) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for item in items {
        if let Some(value) = item.get(key).and_then(Value::as_str) {
            *counts.entry(value.to_string()).or_insert(0) += 1;
        }
    }
    counts
}

fn count_segment(label: &str, counts: BTreeMap<String, usize>) -> Option<String> {
    (!counts.is_empty()).then(|| {
        let items = counts
            .into_iter()
            .map(|(name, count)| format!("{name}={count}"))
            .collect::<Vec<_>>();
        format!("{label} {}", items.join(", "))
    })
}

fn tool_segment(events: &[Value]) -> Option<String> {
    let tools = unique_string_values_at(events, &["tool"]);
    (!tools.is_empty()).then(|| format!("tools {}", tools.join(", ")))
}

fn event_span_segment(events: &[Value]) -> Option<String> {
    let times = events
        .iter()
        .filter_map(|event| u64_at(event, &["atUnix"]))
        .collect::<Vec<_>>();
    let start = times.iter().min()?;
    let end = times.iter().max()?;
    Some(format!("span {}s", end.saturating_sub(*start)))
}

fn unique_string_values_at(items: &[Value], keys: &[&str]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| string_at(item, keys))
        .filter(|value| !value.trim().is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(4)
        .map(str::to_string)
        .collect()
}

fn artifact_count_segment(events: &[Value]) -> Option<String> {
    let count = events
        .iter()
        .filter(|event| event_has_artifact(event))
        .count();
    (count > 0).then(|| format!("artifacts {count}"))
}

fn event_has_artifact(event: &Value) -> bool {
    event.get("artifact").is_some_and(artifact_value_present)
}

fn artifact_value_present(value: &Value) -> bool {
    match value {
        Value::Object(object) => object
            .get("path")
            .and_then(Value::as_str)
            .is_some_and(|path| !path.trim().is_empty()),
        _ => false,
    }
}

fn trace_label(step: &Value) -> Option<&str> {
    step.get("label").and_then(Value::as_str)
}

fn trace_module_segment(steps: &[Value]) -> Option<String> {
    let modules = unique_string_values_at(steps, &["module_id"]);
    (!modules.is_empty()).then(|| format!("modules {}", modules.join(", ")))
}

fn trace_verb_segment(steps: &[Value]) -> Option<String> {
    let verbs = unique_string_values_at(steps, &["verb"]);
    (!verbs.is_empty()).then(|| format!("verbs {}", verbs.join(", ")))
}

fn trace_child_step_segment(steps: &[Value]) -> Option<String> {
    let count = steps
        .iter()
        .filter(|step| u64_at(step, &["parent_step"]).is_some())
        .count();
    (count > 0).then(|| format!("child steps {count}"))
}

fn llm_call_segment(steps: &[Value]) -> Option<String> {
    let count = steps
        .iter()
        .filter(|step| trace_step_has_llm_metadata(step))
        .count();
    (count > 0).then(|| format!("llm calls {count}"))
}

fn trace_step_has_llm_metadata(step: &Value) -> bool {
    string_at(step, &["model", "provider", "prompt_hash"]).is_some()
}

fn trace_latency_segment(steps: &[Value]) -> Option<String> {
    let mut latencies = steps
        .iter()
        .filter_map(|step| u64_at(step, &["latency_ms"]));
    match latencies.try_fold(0_u64, u64::checked_add) {
        Some(0) => None,
        Some(latency) => Some(format!("latency {latency}ms")),
        None => Some("latency invalid".to_string()),
    }
}

fn trace_cost_segment(steps: &[Value]) -> Option<String> {
    let costs = steps
        .iter()
        .filter_map(|step| number_at(step, &["cost_usd"]))
        .collect::<Vec<_>>();
    if costs.is_empty() {
        return None;
    }
    match checked_trace_cost_sum(costs) {
        Some(cost) if cost > 0.0 => Some(format!("cost ${cost:.6}")),
        Some(_) => None,
        None => Some("cost invalid".to_string()),
    }
}

fn checked_trace_cost_sum(costs: impl IntoIterator<Item = f64>) -> Option<f64> {
    costs.into_iter().try_fold(0.0, |total, cost| {
        if !cost.is_finite() || cost < 0.0 {
            return None;
        }
        let next = total + cost;
        next.is_finite().then_some(next)
    })
}

fn number_at<'a>(value: &'a Value, keys: &[&str]) -> Option<f64> {
    keys.iter()
        .filter_map(|key| value.get(*key))
        .find_map(Value::as_f64)
}

fn u64_at(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .filter_map(|key| value.get(*key))
        .find_map(Value::as_u64)
}

fn string_at<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .filter_map(|key| value.get(*key))
        .find_map(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}
