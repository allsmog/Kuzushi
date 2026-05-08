use super::*;

pub(crate) fn string_array(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
        Some(Value::String(value)) if !value.trim().is_empty() => vec![value.trim().to_string()],
        _ => Vec::new(),
    }
}

pub(crate) fn string_record(value: Option<&Value>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    match value {
        Some(Value::Object(object)) => {
            for (key, value) in object {
                if let Some(value) = value
                    .as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    out.insert(key.clone(), value.to_string());
                }
            }
        }
        Some(Value::Array(items)) => {
            for item in items {
                let Some(object) = item.as_object() else {
                    continue;
                };
                let key = string_field(object.get("field"));
                let value = string_field(object.get("value"));
                if !key.is_empty() && !value.is_empty() {
                    out.insert(key, value);
                }
            }
        }
        _ => {}
    }
    out
}

pub(crate) fn string_or_first_array(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(value)) => {
            Some(value.trim().to_string()).filter(|value| !value.is_empty())
        }
        Some(Value::Array(items)) => items
            .iter()
            .find_map(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string),
        _ => None,
    }
}

pub(crate) fn sanitize_rule_segment(value: &str) -> String {
    let mut out = value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>();
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    out.trim_matches('-').to_string()
}

pub(crate) fn trim_line(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed.len() <= 240 {
        trimmed.to_string()
    } else {
        format!("{}...", &trimmed[..240])
    }
}

pub(crate) fn empty_context() -> SystemsContextOutput {
    SystemsContextOutput {
        surfaces: Vec::new(),
        surface_packs: Vec::new(),
        metadata: SystemsContextMetadata {
            codeql_available: false,
            codeql_db_path: None,
            bash_probing_used: false,
        },
    }
}

#[allow(dead_code)]
pub(crate) fn now_isoish() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{seconds}")
}
