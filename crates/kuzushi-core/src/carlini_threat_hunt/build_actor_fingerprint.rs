use super::prelude::*;
use super::*;

pub(super) fn build_actor_fingerprint(actor: &DfdNode, run_index: usize) -> String {
    let sanitized = actor
        .name
        .chars()
        .map(|ch| {
            if ch.is_whitespace() || ch == ':' {
                '_'
            } else {
                ch
            }
        })
        .collect::<String>();
    format!("{MODULE_ID}:{sanitized}:{run_index}")
}

pub(super) fn require_json_object(value: Value) -> Result<Value> {
    if value.is_object() {
        return Ok(value);
    }
    anyhow::bail!("carlini-threat-hunt structured output must be a JSON object")
}

pub(super) fn findings_schema() -> Value {
    json!({
        "type": "object",
        "required": ["findings"],
        "additionalProperties": true,
        "properties": {
            "findings": {"type": "array", "items": {"type": "object"}}
        }
    })
}

pub(super) fn normalize_file_path(target: &Path, file_path: &str) -> Option<String> {
    let path = PathBuf::from(file_path.trim());
    if path.is_absolute() {
        return path
            .strip_prefix(target)
            .ok()
            .map(|path| path.display().to_string());
    }
    if file_path.trim().starts_with("..") {
        return None;
    }
    Some(file_path.trim().to_string())
}

pub(super) fn carlini_severity(value: &str) -> Severity {
    match value.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "ERROR" | "HIGH" => Severity::High,
        "WARNING" | "MEDIUM" => Severity::Medium,
        "INFO" | "LOW" => Severity::Low,
        _ => Severity::Unknown,
    }
}

pub(super) fn critical_count(threats: &[Value]) -> usize {
    threats
        .iter()
        .filter(|threat| {
            object_string_value(threat, &["impact"])
                .is_some_and(|impact| impact.eq_ignore_ascii_case("critical"))
        })
        .count()
}

pub(super) fn optional_string(input: &Value, keys: &[&str]) -> Result<Option<String>> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return match value {
                Value::String(text) => {
                    Ok(Some(text.trim().to_string()).filter(|text| !text.is_empty()))
                }
                _ => anyhow::bail!("carlini-threat-hunt:run {key} must be a string"),
            };
        }
    }
    Ok(None)
}

pub(super) fn read_usize(input: &Value, keys: &[&str], fallback: usize, min: usize) -> usize {
    for key in keys {
        if let Some(value) = input.get(*key) {
            let parsed = match value {
                Value::Number(number) => number.as_u64().map(|value| value as usize),
                Value::String(text) => text.parse::<usize>().ok(),
                _ => None,
            };
            return parsed.filter(|value| *value >= min).unwrap_or(fallback);
        }
    }
    fallback
}

pub(super) fn bool_input(input: &Value, keys: &[&str], fallback: bool) -> bool {
    keys.iter()
        .find_map(|key| input.get(*key).and_then(Value::as_bool))
        .unwrap_or(fallback)
}

pub(super) fn resolve_prompt_override(value: &str, cwd: &Path) -> Result<String> {
    if !looks_like_prompt_path(value) {
        return Ok(value.to_string());
    }
    let path = Path::new(value);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    fs::read_to_string(&path).with_context(|| {
        format!(
            "Could not read CARLINI_THREAT_HUNT_PROMPT from {}",
            path.display()
        )
    })
}

pub(super) fn looks_like_prompt_path(value: &str) -> bool {
    value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || value.ends_with(".md")
        || value.ends_with(".txt")
        || value.ends_with(".prompt")
}

pub(super) fn object_string_value(value: &Value, keys: &[&str]) -> Option<String> {
    let object = value.as_object()?;
    read_object_string(object, keys)
}

pub(super) fn object_string_array(value: &Value, keys: &[&str]) -> Vec<String> {
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    for key in keys {
        if let Some(Value::Array(items)) = object.get(*key) {
            return items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect();
        }
    }
    Vec::new()
}

pub(super) fn read_object_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(super) fn read_object_u64(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| object.get(*key))
        .and_then(Value::as_u64)
}

pub(super) fn read_object_string_array(object: &Map<String, Value>, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .find_map(|key| object.get(*key))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for value in values {
        if !value.trim().is_empty() && seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}

pub(super) fn should_skip_path(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".kuzushi"
            | ".next"
            | ".turbo"
            | "coverage"
            | "dist"
            | "native"
            | "node_modules"
            | "target"
    )
}

pub(super) fn is_context_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if matches!(
        name,
        "package.json" | "Cargo.toml" | "pyproject.toml" | "go.mod" | "pom.xml"
    ) {
        return true;
    }
    matches!(
        path.extension().and_then(|ext| ext.to_str()).unwrap_or(""),
        "c" | "cc"
            | "cpp"
            | "cs"
            | "go"
            | "java"
            | "js"
            | "jsx"
            | "kt"
            | "php"
            | "py"
            | "rb"
            | "rs"
            | "sol"
            | "ts"
            | "tsx"
    )
}
