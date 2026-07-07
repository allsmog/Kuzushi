use super::*;

pub(crate) fn summarize_taint_path(object: &Map<String, Value>) -> Option<String> {
    let path = read_object_value(object, &["taintPath", "taint_path"])?.as_array()?;
    let mut lines = Vec::new();
    for item in path.iter().take(20) {
        let Value::Object(step) = item else {
            continue;
        };
        let file_path = read_object_string(step, &["filePath", "file_path"])
            .unwrap_or_else(|| "unknown".to_string());
        let line = read_object_u64(step, &["line", "startLine", "start_line"]).unwrap_or(1);
        let message = read_object_string(step, &["message"]).unwrap_or_default();
        let snippet = read_object_string(step, &["snippet"]).unwrap_or_default();
        let mut rendered = format!("- {file_path}:{line}");
        if !message.is_empty() {
            rendered.push_str(": ");
            rendered.push_str(&message);
        }
        if !snippet.is_empty() {
            rendered.push_str(" | ");
            rendered.push_str(&snippet);
        }
        lines.push(rendered);
    }
    (!lines.is_empty()).then(|| lines.join("\n"))
}

pub(crate) fn sanitize_rule_segment(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    sanitized.trim_matches('-').to_string()
}

pub(crate) fn read_object_value<'a>(
    object: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

pub(crate) fn read_object_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    read_object_value(object, keys)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(crate) fn read_object_u64(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    read_object_value(object, keys).and_then(Value::as_u64)
}
