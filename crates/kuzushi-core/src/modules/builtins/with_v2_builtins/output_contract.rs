use serde_json::{json, Map, Value};

pub(super) fn normalize_tool_output_contract(name: &str, output: Value) -> Value {
    if is_catalog_metadata_tool(name) {
        return output;
    }
    normalize_output_value(output)
}

fn normalize_output_value(output: Value) -> Value {
    match output {
        Value::Object(mut object) => {
            ensure_contract_fields(&mut object);
            Value::Object(object)
        }
        other => json!({
            "ok": true,
            "status": "completed",
            "summary": "tool returned a non-object value",
            "artifacts": [],
            "warnings": [],
            "errors": [],
            "data": other,
        }),
    }
}

fn is_catalog_metadata_tool(name: &str) -> bool {
    matches!(name, "catalog:modules" | "catalog:tools")
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
    let artifacts = inferred_artifacts(object);
    object.insert("artifacts".to_string(), artifacts);
    object.insert(
        "warnings".to_string(),
        message_array_field(object, "warnings", "warning"),
    );
    object.insert(
        "errors".to_string(),
        message_array_field(object, "errors", "error"),
    );
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
    object
        .get("ok")
        .and_then(Value::as_bool)
        .unwrap_or(true)
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
        "completed" | "complete" | "ok" | "success" => Some("completed"),
        "partial" => Some("partial"),
        "skipped" | "skip" => Some("skipped"),
        "failed" | "error" => Some("failed"),
        _ => None,
    }
}

fn inferred_summary(object: &Map<String, Value>, status: &str, summary: Option<&Value>) -> Value {
    string_summary(summary)
        .or_else(|| object.get("data").and_then(|data| string_summary(data.get("summary"))))
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
    Some(json!(summary.chars().take(MAX_SUMMARY_CHARS).collect::<String>()))
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
    ARTIFACT_PATH_KEYS
        .iter()
        .any(|key| object.get(*key).and_then(Value::as_str).is_some())
}

fn first_path_string<'a>(object: &'a Map<String, Value>) -> Option<&'a str> {
    ARTIFACT_PATH_KEYS
        .iter()
        .filter_map(|key| object.get(*key))
        .find_map(Value::as_str)
}

fn preserve_domain_status(object: &mut Map<String, Value>, status: Option<&Value>) {
    let Some(status) = unknown_status_value(status) else {
        return;
    };
    let data = object.entry("data".to_string()).or_insert_with(|| json!({}));
    if let Value::Object(data) = data {
        data.entry("status".to_string()).or_insert(status);
    }
}

fn preserve_domain_summary(object: &mut Map<String, Value>, summary: Option<&Value>) {
    let Some(summary) = structured_summary_value(summary) else {
        return;
    };
    let data = object.entry("data".to_string()).or_insert_with(|| json!({}));
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

const ARTIFACT_PATH_KEYS: [&str; 9] = [
    "path",
    "file",
    "filePath",
    "reportPath",
    "reportJsonPath",
    "scopePath",
    "dir",
    "outputDir",
    "promptsDir",
];

const MAX_SUMMARY_CHARS: usize = 160;

#[cfg(test)]
#[path = "output_contract_tests.rs"]
mod tests;
