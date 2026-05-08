use super::prelude::*;
use super::*;

pub(crate) fn require_json_object(value: Value) -> Result<Value> {
    if value.is_object() {
        Ok(value)
    } else {
        anyhow::bail!("variant/ndiff structured output must be a JSON object")
    }
}

pub(crate) fn object_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": true
    })
}

pub(crate) fn findings_schema() -> Value {
    json!({
        "type": "object",
        "required": ["variants"],
        "additionalProperties": true,
        "properties": {
            "variants": {"type": "array", "items": {"type": "object"}},
            "findings": {"type": "array", "items": {"type": "object"}}
        }
    })
}

pub(crate) fn resolve_tool_target(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PathBuf> {
    if let Some(target) = input.get("target").and_then(Value::as_str) {
        let trimmed = target.trim();
        let path = if trimmed.is_empty() {
            std::env::current_dir().context("Could not resolve current directory")?
        } else {
            let candidate = PathBuf::from(trimmed);
            if candidate.is_absolute() {
                candidate
            } else {
                std::env::current_dir()
                    .context("Could not resolve current directory")?
                    .join(candidate)
            }
        };
        return Ok(path);
    }
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    std::env::current_dir().context("Could not resolve current directory")
}

pub(crate) fn positive_usize_input(input: &Value, key: &str, default: usize, max: usize) -> usize {
    input
        .get(key)
        .and_then(|value| match value {
            Value::Number(number) => number.as_u64().map(|value| value as usize),
            Value::String(text) => text.parse::<usize>().ok(),
            _ => None,
        })
        .filter(|value| *value > 0)
        .unwrap_or(default)
        .min(max)
}

pub(crate) fn vendor_paths_from_input(input: &Value) -> Vec<String> {
    input
        .get("vendorPaths")
        .or_else(|| input.get("vendor_paths"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| {
            DEFAULT_VENDOR_PATHS
                .iter()
                .map(|path| (*path).to_string())
                .collect()
        })
}

pub(crate) fn normalize_file_path(root: &Path, file_path: &str) -> String {
    let candidate = PathBuf::from(file_path.trim());
    if candidate.is_absolute() {
        return candidate
            .strip_prefix(root)
            .unwrap_or(&candidate)
            .display()
            .to_string();
    }
    file_path.trim().to_string()
}

pub(crate) fn severity_from_agent(value: &str) -> Severity {
    match value.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "ERROR" | "HIGH" => Severity::High,
        "WARNING" | "MEDIUM" => Severity::Medium,
        "INFO" | "LOW" => Severity::Low,
        _ => Severity::Unknown,
    }
}

pub(crate) fn read_object_value<'a>(
    object: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}
