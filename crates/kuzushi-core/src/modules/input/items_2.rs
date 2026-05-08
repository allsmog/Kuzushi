use super::prelude::*;
use super::*;

pub(in crate::modules) fn parse_sast_severity_filter(
    input: &Value,
) -> Result<Option<Vec<Severity>>> {
    let Some(values) = string_list_input(input, &["severity"])? else {
        return Ok(None);
    };
    if values.is_empty() {
        return Ok(None);
    }
    values
        .iter()
        .map(|value| parse_sast_severity(value))
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

pub(in crate::modules) fn parse_sast_severity(value: &str) -> Result<Severity> {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => Ok(Severity::Critical),
        "high" | "error" => Ok(Severity::High),
        "medium" | "warning" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        "info" => Ok(Severity::Info),
        "unknown" => Ok(Severity::Unknown),
        other => anyhow::bail!("sast:scan unknown severity filter {other:?}"),
    }
}

pub(in crate::modules) fn string_list_input(
    input: &Value,
    keys: &[&str],
) -> Result<Option<Vec<String>>> {
    let Some(raw) = keys.iter().find_map(|key| input.get(*key)) else {
        return Ok(None);
    };
    let values = match raw {
        Value::String(value) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
        Value::Array(items) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
                    .context("sast:scan list inputs must contain only non-empty strings")
            })
            .collect::<Result<Vec<_>>>()?,
        _ => anyhow::bail!("sast:scan list inputs must be a string or string array"),
    };
    Ok(Some(values))
}

pub(in crate::modules) fn bool_input(input: &Value, keys: &[&str]) -> Result<bool> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return value
                .as_bool()
                .with_context(|| format!("sast:scan {key} must be a boolean"));
        }
    }
    Ok(false)
}

pub(in crate::modules) fn same_scan_task(left: &str, right: &str) -> bool {
    let left = left.trim();
    let right = right.trim();
    left == right || left.split(':').next() == right.split(':').next()
}

pub(in crate::modules) fn optional_nonempty_string(
    input: &Value,
    key: &str,
) -> Result<Option<String>> {
    match input.get(key) {
        Some(Value::String(value)) => Ok(Some(value.trim().to_string()).filter(|s| !s.is_empty())),
        Some(_) => anyhow::bail!("triage:run {key} must be a string"),
        None => Ok(None),
    }
}

pub(in crate::modules) fn resolve_prompt_override(value: &str, cwd: &Path) -> Result<String> {
    resolve_prompt_override_for_key(value, cwd, "TRIAGE_PROMPT")
}

pub(in crate::modules) fn resolve_prompt_override_for_key(
    value: &str,
    cwd: &Path,
    key: &str,
) -> Result<String> {
    if !looks_like_prompt_path(value) {
        return Ok(value.to_string());
    }
    let path = Path::new(value);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    fs::read_to_string(&path)
        .with_context(|| format!("Could not read {key} from {}", path.display()))
}

pub(in crate::modules) fn looks_like_prompt_path(value: &str) -> bool {
    value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || value.ends_with(".md")
        || value.ends_with(".txt")
        || value.ends_with(".prompt")
}
