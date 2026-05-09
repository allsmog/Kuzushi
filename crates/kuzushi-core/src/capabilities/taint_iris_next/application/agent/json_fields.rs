use super::*;

pub(in crate::capabilities::taint_iris_next) fn read_object_value<'a>(
    object: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

pub(in crate::capabilities::taint_iris_next) fn read_object_string(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    read_object_value(object, keys)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(in crate::capabilities::taint_iris_next) fn read_object_u64(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<u64> {
    read_object_value(object, keys).and_then(Value::as_u64)
}

pub(in crate::capabilities::taint_iris_next) fn read_object_string_array(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Vec<String> {
    read_object_value(object, keys)
        .and_then(Value::as_array)
        .map(|items| nonempty_string_values(items))
        .unwrap_or_default()
}

fn nonempty_string_values(items: &[Value]) -> Vec<String> {
    items
        .iter()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

pub(in crate::capabilities::taint_iris_next) fn parse_json_object_from_agent_text(
    text: &str,
) -> Result<Value> {
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        return Ok(value);
    }
    parse_json_object_slice(text)
}

fn parse_json_object_slice(text: &str) -> Result<Value> {
    let start = text
        .find('{')
        .context("verification output parse failed: missing JSON object start")?;
    let end = text
        .rfind('}')
        .context("verification output parse failed: missing JSON object end")?;
    parse_json_object_range(text, start, end)
}

fn parse_json_object_range(text: &str, start: usize, end: usize) -> Result<Value> {
    if end < start {
        anyhow::bail!("verification output parse failed: malformed JSON object");
    }
    serde_json::from_str(&text[start..=end])
        .with_context(|| "verification output parse failed: invalid JSON object")
}

pub(in crate::capabilities::taint_iris_next) fn normalize_reported_file_path(
    path: String,
    target: &Path,
) -> String {
    let trimmed = path.trim();
    let candidate = PathBuf::from(trimmed);
    if candidate.is_absolute() {
        return candidate
            .strip_prefix(target)
            .unwrap_or(&candidate)
            .display()
            .to_string();
    }
    trimmed.to_string()
}
