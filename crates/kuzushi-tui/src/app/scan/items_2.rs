use super::prelude::*;
use super::*;

pub(crate) fn truncate_ascii(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut truncated = value
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>();
    truncated.push_str("...");
    truncated
}

pub(crate) fn parse_scan_severity_filter(
    input: &serde_json::Value,
) -> Result<Option<Vec<Severity>>> {
    let Some(raw) = input.get("severity") else {
        return Ok(None);
    };
    let values = match raw {
        serde_json::Value::String(value) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        serde_json::Value::Array(items) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
                    .context("scan severity must contain only non-empty strings")
            })
            .collect::<Result<Vec<_>>>()?,
        other => {
            anyhow::bail!("scan severity must be a string or string array, got {other}");
        }
    };
    if values.is_empty() {
        return Ok(None);
    }
    values
        .iter()
        .map(|value| match value.trim().to_ascii_lowercase().as_str() {
            "critical" => Ok(Severity::Critical),
            "high" | "error" => Ok(Severity::High),
            "medium" | "warning" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            "info" => Ok(Severity::Info),
            "unknown" => Ok(Severity::Unknown),
            other => anyhow::bail!("scan unknown severity filter {other:?}"),
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}
