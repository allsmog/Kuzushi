use serde_json::{json, Map, Value};

mod envelope;

pub use envelope::failed_tool_output;
pub(crate) use envelope::{
    completed_output_result, failed_output_result, partial_output_result, skipped_output_result,
};

#[cfg(test)]
mod subprocess_failure_summary_tests;

/// Distill captured subprocess stderr into a single actionable line for an
/// error message or banner — skipping JVM/stack-frame noise (`at …`,
/// `… N more`) so the operator sees the cause, not the call stack.
pub(crate) fn subprocess_failure_summary(stderr: &[u8], fallback: &str) -> String {
    let text = String::from_utf8_lossy(stderr);
    let meaningful: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !is_stack_noise(line))
        .collect();
    // Prefer a line that names a specific, actionable cause; then any
    // failure-ish line; then the last meaningful line; then the caller's hint.
    meaningful
        .iter()
        .find(|line| names_a_failure(line) && !is_generic_wrapper(line))
        .or_else(|| meaningful.iter().find(|line| names_a_failure(line)))
        .or_else(|| meaningful.last())
        .map(|line| strip_log_prefix(line).to_string())
        .unwrap_or_else(|| fallback.to_string())
}

fn is_stack_noise(line: &str) -> bool {
    line.starts_with("at ") || (line.starts_with("...") && line.ends_with("more"))
}

fn names_a_failure(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "error",
        "not found",
        "no such",
        "missing",
        "cannot",
        "could not",
        "failed",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// Generic exit-code wrappers carry no actionable detail — skip them in favor
/// of the line that names the real cause (e.g. a missing dependency).
fn is_generic_wrapper(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("process exited with code") || lower.contains("externalcommand")
}

/// Drop a leading `<timestamp> LEVEL Logger` prefix that tools like joern emit,
/// leaving just the message.
fn strip_log_prefix(line: &str) -> &str {
    for level in ["ERROR ", "WARN ", "FATAL ", "SEVERE "] {
        if let Some(idx) = line.find(level) {
            let rest = line[idx + level.len()..].trim_start();
            // Skip the logger name token that usually follows the level.
            if let Some((_, message)) = rest.split_once("  ") {
                return message.trim_start();
            }
            return rest;
        }
    }
    line
}

pub(crate) fn normalize_module_result(output: Value) -> Value {
    match output {
        Value::Object(mut object) => {
            ensure_contract_fields(&mut object);
            Value::Object(object)
        }
        other => completed_output_result(
            "tool returned a non-object value",
            "tool returned a non-object value",
            other,
        ),
    }
}

fn ensure_contract_fields(object: &mut Map<String, Value>) {
    let original_status = object.get("status").cloned();
    let original_summary = object.get("summary").cloned();
    let status = inferred_status(object);
    preserve_domain_status(object, original_status.as_ref());
    preserve_domain_summary(object, original_summary.as_ref());
    object.insert("ok".to_string(), json!(inferred_ok(object, &status)));
    object.insert("status".to_string(), json!(status));
    object.insert(
        "summary".to_string(),
        inferred_summary(object, &status, original_summary.as_ref()),
    );
    object.insert("artifacts".to_string(), inferred_artifacts(object));
    object.insert(
        "warnings".to_string(),
        message_array_field(object, "warnings", "warning"),
    );
    object.insert("errors".to_string(), error_array_field(object, &status));
}

fn inferred_status(object: &Map<String, Value>) -> String {
    if object.get("ok").and_then(Value::as_bool) == Some(false) {
        return "failed".to_string();
    }
    if let Some(status) = object
        .get("status")
        .and_then(Value::as_str)
        .and_then(canonical_status)
    {
        return status.to_string();
    }
    nested_status(object).unwrap_or("completed").to_string()
}

fn inferred_ok(object: &Map<String, Value>, status: &str) -> bool {
    if status == "failed" {
        return false;
    }
    object.get("ok").and_then(Value::as_bool).unwrap_or(true)
}

fn nested_status(object: &Map<String, Value>) -> Option<&'static str> {
    let status = object
        .get("data")
        .and_then(|data| data.get("status"))
        .and_then(Value::as_str)?;
    canonical_status(status)
}

fn canonical_status(status: &str) -> Option<&'static str> {
    match status.trim().to_ascii_lowercase().as_str() {
        "completed" => Some("completed"),
        "partial" => Some("partial"),
        "skipped" => Some("skipped"),
        "failed" => Some("failed"),
        _ => None,
    }
}

fn inferred_summary(object: &Map<String, Value>, status: &str, summary: Option<&Value>) -> Value {
    string_summary(summary)
        .or_else(|| {
            object
                .get("data")
                .and_then(|data| string_summary(data.get("summary")))
        })
        .or_else(|| output_summary(object))
        .unwrap_or_else(|| json!(format!("tool {status}")))
}

fn string_summary(value: Option<&Value>) -> Option<Value> {
    let summary = value?.as_str()?.trim();
    (!summary.is_empty()).then(|| json!(summary))
}

fn output_summary(object: &Map<String, Value>) -> Option<Value> {
    let summary = object
        .get("output")
        .and_then(Value::as_str)?
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())?;
    Some(json!(summary
        .chars()
        .take(MAX_SUMMARY_CHARS)
        .collect::<String>()))
}

fn inferred_artifacts(object: &Map<String, Value>) -> Value {
    let top_level = artifact_array(object.get("artifacts"));
    if !top_level.is_empty() {
        return json!(top_level);
    }
    let nested = artifact_array(object.get("data").and_then(|data| data.get("artifacts")));
    if nested.is_empty() {
        json!(top_level)
    } else {
        json!(nested)
    }
}

fn artifact_array(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(items)) => artifact_items("artifact", items),
        Some(Value::Object(object)) if has_path_key(object) => {
            artifact_object("artifact", object).into_iter().collect()
        }
        Some(Value::Object(object)) => object
            .iter()
            .filter_map(|(label, value)| artifact_item(label, value))
            .collect(),
        Some(Value::String(path)) => artifact_path("artifact", path).into_iter().collect(),
        _ => Vec::new(),
    }
}

fn artifact_items(label: &str, values: &[Value]) -> Vec<Value> {
    values
        .iter()
        .filter_map(|value| artifact_item(label, value))
        .collect()
}

fn artifact_item(label: &str, value: &Value) -> Option<Value> {
    match value {
        Value::Object(object) => artifact_object(label, object),
        Value::String(path) => artifact_path(label, path),
        _ => None,
    }
}

fn artifact_object(label: &str, object: &Map<String, Value>) -> Option<Value> {
    let path = first_path_string(object)?;
    if path.trim().is_empty() {
        return None;
    }
    let mut normalized = object.clone();
    normalized
        .entry("path".to_string())
        .or_insert_with(|| json!(path));
    normalized
        .entry("label".to_string())
        .or_insert_with(|| json!(label));
    Some(Value::Object(normalized))
}

fn artifact_path(label: &str, path: &str) -> Option<Value> {
    (!path.trim().is_empty()).then(|| json!({ "label": label, "path": path }))
}

fn has_path_key(object: &Map<String, Value>) -> bool {
    object.get("path").and_then(Value::as_str).is_some()
}

fn first_path_string<'a>(object: &'a Map<String, Value>) -> Option<&'a str> {
    object.get("path").and_then(Value::as_str)
}

fn preserve_domain_status(object: &mut Map<String, Value>, status: Option<&Value>) {
    let Some(status) = unknown_status_value(status) else {
        return;
    };
    let data = object
        .entry("data".to_string())
        .or_insert_with(|| json!({}));
    if let Value::Object(data) = data {
        data.entry("status".to_string()).or_insert(status);
    }
}

fn preserve_domain_summary(object: &mut Map<String, Value>, summary: Option<&Value>) {
    let Some(summary) = structured_summary_value(summary) else {
        return;
    };
    let data = object
        .entry("data".to_string())
        .or_insert_with(|| json!({}));
    if let Value::Object(data) = data {
        data.entry("summary".to_string()).or_insert(summary);
    }
}

fn unknown_status_value(status: Option<&Value>) -> Option<Value> {
    let status = status?.as_str()?;
    canonical_status(status).is_none().then(|| json!(status))
}

fn structured_summary_value(summary: Option<&Value>) -> Option<Value> {
    let summary = summary?;
    (!summary.is_string()).then(|| summary.clone())
}

fn error_array_field(object: &Map<String, Value>, status: &str) -> Value {
    message_array(object.get("errors"))
        .or_else(|| message_array(object.get("error")))
        .or_else(|| failed_summary_error(object, status))
        .map(Value::Array)
        .unwrap_or_else(|| json!([]))
}

fn failed_summary_error(object: &Map<String, Value>, status: &str) -> Option<Vec<Value>> {
    if status != "failed" {
        return None;
    }
    string_summary(object.get("summary")).map(|message| vec![message])
}

fn message_array_field(object: &Map<String, Value>, primary: &str, alias: &str) -> Value {
    message_array(object.get(primary))
        .or_else(|| message_array(object.get(alias)))
        .map(Value::Array)
        .unwrap_or_else(|| json!([]))
}

fn message_array(value: Option<&Value>) -> Option<Vec<Value>> {
    match value? {
        Value::Array(items) => Some(items.iter().filter_map(message_value).collect()),
        other => message_value(other).map(|message| vec![message]),
    }
}

fn message_value(value: &Value) -> Option<Value> {
    match value {
        Value::String(message) if !message.trim().is_empty() => Some(json!(message)),
        Value::Object(_) => Some(value.clone()),
        _ => None,
    }
}

const MAX_SUMMARY_CHARS: usize = 160;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_object_output_normalizes_through_completed_envelope() {
        let output = normalize_module_result(json!(["a", "b"]));

        assert_eq!(output["ok"], json!(true));
        assert_eq!(output["status"], json!("completed"));
        assert_eq!(output["summary"], json!("tool returned a non-object value"));
        assert_eq!(output["output"], json!("tool returned a non-object value"));
        assert_eq!(output["data"], json!(["a", "b"]));
        assert!(output["artifacts"].as_array().unwrap().is_empty());
        assert!(output["warnings"].as_array().unwrap().is_empty());
        assert!(output["errors"].as_array().unwrap().is_empty());
    }
}
