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
    let normalized = value.trim().to_ascii_lowercase();
    SAST_SEVERITY_ALIASES
        .iter()
        .find_map(|(alias, severity)| (*alias == normalized).then_some(*severity))
        .with_context(|| format!("sast:scan unknown severity filter {normalized:?}"))
}

const SAST_SEVERITY_ALIASES: &[(&str, Severity)] = &[
    ("critical", Severity::Critical),
    ("high", Severity::High),
    ("error", Severity::High),
    ("medium", Severity::Medium),
    ("warning", Severity::Medium),
    ("low", Severity::Low),
    ("info", Severity::Info),
    ("unknown", Severity::Unknown),
];

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

pub(in crate::modules) fn optional_string_input(
    input: &Value,
    keys: &[&str],
) -> Result<Option<String>> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .with_context(|| format!("sast:scan {key} must be a non-empty string"))
                .map(Some);
        }
    }
    Ok(None)
}

pub(in crate::modules) fn optional_usize_input(
    input: &Value,
    keys: &[&str],
) -> Result<Option<usize>> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            let raw = value
                .as_u64()
                .with_context(|| format!("sast:scan {key} must be a positive integer"))?;
            if raw == 0 {
                anyhow::bail!("sast:scan {key} must be greater than zero");
            }
            return usize::try_from(raw)
                .with_context(|| format!("sast:scan {key} is too large"))
                .map(Some);
        }
    }
    Ok(None)
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
    crate::options::resolve_prepared_prompt_override_for_key(
        value,
        cwd,
        "TRIAGE_PROMPT",
        crate::runtime::DEFAULT_TRIAGE_PROMPT,
    )
}
