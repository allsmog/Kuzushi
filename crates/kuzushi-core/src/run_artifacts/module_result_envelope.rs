use serde_json::{json, Map, Value};

pub(crate) fn normalized_module_result(tool: &str, status: &str, output: Value) -> Value {
    match output {
        Value::Object(mut object) => {
            normalize_object(tool, status, &mut object);
            Value::Object(object)
        }
        data => wrapped_result(tool, status, data),
    }
}

fn normalize_object(tool: &str, status: &str, object: &mut Map<String, Value>) {
    object.insert("status".to_string(), Value::String(status.to_string()));
    normalize_ok(status, object);
    object
        .entry("summary".to_string())
        .or_insert_with(|| Value::String(default_summary(tool, status)));
    object
        .entry("artifacts".to_string())
        .or_insert_with(|| json!([]));
    normalize_message_array(object, "warnings", Vec::new());
    let errors = default_errors(status, object);
    normalize_message_array(object, "errors", errors);
}

fn normalize_ok(status: &str, object: &mut Map<String, Value>) {
    if status == "failed" {
        object.insert("ok".to_string(), Value::Bool(false));
        return;
    }
    object.entry("ok".to_string()).or_insert(Value::Bool(true));
}

fn wrapped_result(tool: &str, status: &str, data: Value) -> Value {
    json!({
        "ok": status != "failed",
        "status": status,
        "summary": default_summary(tool, status),
        "artifacts": [],
        "warnings": [],
        "errors": [],
        "data": data,
    })
}

fn normalize_message_array(object: &mut Map<String, Value>, key: &str, fallback: Vec<Value>) {
    let value = object.remove(key);
    object.insert(key.to_string(), message_array(value, fallback));
}

fn message_array(value: Option<Value>, fallback: Vec<Value>) -> Value {
    match value {
        Some(Value::Array(items)) => Value::Array(items),
        Some(Value::Null) | None => Value::Array(fallback),
        Some(value) => Value::Array(vec![value]),
    }
}

fn default_errors(status: &str, object: &Map<String, Value>) -> Vec<Value> {
    if status != "failed" {
        return Vec::new();
    }
    object
        .get("error")
        .and_then(Value::as_str)
        .or_else(|| object.get("summary").and_then(Value::as_str))
        .map(|message| vec![Value::String(message.to_string())])
        .unwrap_or_default()
}

fn default_summary(tool: &str, status: &str) -> String {
    match status {
        "failed" => format!("{tool} failed"),
        "partial" => format!("{tool} partially completed"),
        "skipped" => format!("{tool} skipped"),
        _ => format!("{tool} completed"),
    }
}
