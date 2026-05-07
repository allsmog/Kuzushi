use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;

use crate::findings::Severity;

pub(super) fn optional_taint_next_string(input: &Value, keys: &[&str]) -> Result<Option<String>> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return match value {
                Value::String(text) => Ok(Some(text.trim().to_string()).filter(|s| !s.is_empty())),
                _ => anyhow::bail!("taint-iris-next:hunt {key} must be a string"),
            };
        }
    }
    Ok(None)
}

pub(super) fn positive_usize_input(
    input: &Value,
    keys: &[&str],
    label: &str,
) -> Result<Option<usize>> {
    let Some(value) = keys.iter().find_map(|key| input.get(*key)) else {
        return Ok(None);
    };
    match value {
        Value::Number(number) => {
            let value = number
                .as_u64()
                .with_context(|| format!("{label} must be a positive integer"))?;
            if value == 0 {
                anyhow::bail!("{label} must be a positive integer");
            }
            Ok(Some(value as usize))
        }
        Value::String(value) => {
            let parsed = value
                .trim()
                .parse::<usize>()
                .with_context(|| format!("{label} must be a positive integer"))?;
            if parsed == 0 {
                anyhow::bail!("{label} must be a positive integer");
            }
            Ok(Some(parsed))
        }
        _ => anyhow::bail!("{label} must be a positive integer"),
    }
}

pub(super) fn positive_f64_input(input: &Value, keys: &[&str], label: &str) -> Result<Option<f64>> {
    let Some(value) = keys.iter().find_map(|key| input.get(*key)) else {
        return Ok(None);
    };
    let parsed = match value {
        Value::Number(number) => number
            .as_f64()
            .with_context(|| format!("{label} must be a positive number"))?,
        Value::String(value) => value
            .trim()
            .parse::<f64>()
            .with_context(|| format!("{label} must be a positive number"))?,
        _ => anyhow::bail!("{label} must be a positive number"),
    };
    if !parsed.is_finite() || parsed <= 0.0 {
        anyhow::bail!("{label} must be a positive number");
    }
    Ok(Some(parsed))
}

pub(super) fn parse_sast_tasks(input: &Value) -> Result<Vec<String>> {
    let requested = string_list_input(input, &["tasks", "taskIds", "task_ids"])?;
    let disabled =
        string_list_input(input, &["disabledTasks", "disabled_tasks"])?.unwrap_or_default();
    let task_mode = input
        .get("taskMode")
        .or_else(|| input.get("task_mode"))
        .and_then(Value::as_str)
        .unwrap_or("auto");
    if !matches!(task_mode, "auto" | "manual") {
        anyhow::bail!("sast:scan taskMode must be \"auto\" or \"manual\"");
    }
    if task_mode == "manual" && requested.as_ref().map_or(true, Vec::is_empty) {
        anyhow::bail!("sast:scan taskMode=manual requires a non-empty tasks array");
    }

    let mut tasks = requested.unwrap_or_else(|| {
        if disabled.is_empty() {
            Vec::new()
        } else {
            vec![
                "semgrep".to_string(),
                "dep-hygiene".to_string(),
                "secret-scan".to_string(),
                "iac-scan".to_string(),
            ]
        }
    });

    if !disabled.is_empty() {
        tasks.retain(|task| {
            !disabled
                .iter()
                .any(|disabled| same_scan_task(task, disabled))
        });
    }
    Ok(tasks)
}

pub(super) fn parse_sast_severity_filter(input: &Value) -> Result<Option<Vec<Severity>>> {
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

fn parse_sast_severity(value: &str) -> Result<Severity> {
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

pub(super) fn string_list_input(input: &Value, keys: &[&str]) -> Result<Option<Vec<String>>> {
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

pub(super) fn bool_input(input: &Value, keys: &[&str]) -> Result<bool> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return value
                .as_bool()
                .with_context(|| format!("sast:scan {key} must be a boolean"));
        }
    }
    Ok(false)
}

pub(super) fn same_scan_task(left: &str, right: &str) -> bool {
    let left = left.trim();
    let right = right.trim();
    left == right || left.split(':').next() == right.split(':').next()
}

pub(super) fn optional_nonempty_string(input: &Value, key: &str) -> Result<Option<String>> {
    match input.get(key) {
        Some(Value::String(value)) => Ok(Some(value.trim().to_string()).filter(|s| !s.is_empty())),
        Some(_) => anyhow::bail!("triage:run {key} must be a string"),
        None => Ok(None),
    }
}

pub(super) fn resolve_prompt_override(value: &str, cwd: &Path) -> Result<String> {
    resolve_prompt_override_for_key(value, cwd, "TRIAGE_PROMPT")
}

pub(super) fn resolve_prompt_override_for_key(
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

fn looks_like_prompt_path(value: &str) -> bool {
    value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || value.ends_with(".md")
        || value.ends_with(".txt")
        || value.ends_with(".prompt")
}

pub(super) fn string_input_any(input: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        input
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

pub(super) fn string_array_or_csv_input(input: &Value, keys: &[&str]) -> Option<Vec<String>> {
    keys.iter().find_map(|key| match input.get(*key) {
        Some(Value::String(value)) => Some(
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect(),
        ),
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect(),
        ),
        _ => None,
    })
}

pub(super) fn read_bool_any(input: &Value, keys: &[&str]) -> Result<Option<bool>> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return value
                .as_bool()
                .map(Some)
                .with_context(|| format!("{key} must be a boolean"));
        }
    }
    Ok(None)
}

pub(super) fn resolve_input_path(root: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value.trim());
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn positive_f64_input_accepts_numbers_and_strings_and_rejects_bad_values() {
        assert_eq!(
            positive_f64_input(&json!({"cap": 1.5}), &["cap"], "cap")
                .unwrap()
                .unwrap(),
            1.5
        );
        assert_eq!(
            positive_f64_input(&json!({"cap_text": "2.75"}), &["cap", "cap_text"], "cap")
                .unwrap()
                .unwrap(),
            2.75
        );
        assert!(positive_f64_input(&json!({}), &["cap"], "cap")
            .unwrap()
            .is_none());

        for input in [
            json!({"cap": 0.0}),
            json!({"cap": -1.0}),
            json!({"cap": "NaN"}),
            json!({"cap": true}),
        ] {
            assert!(positive_f64_input(&input, &["cap"], "cap").is_err());
        }
    }

    #[test]
    fn prompt_path_detection_covers_relative_absolute_and_plain_text() {
        assert!(looks_like_prompt_path("./prompt.md"));
        assert!(looks_like_prompt_path("../prompt.txt"));
        assert!(looks_like_prompt_path("/tmp/prompt.prompt"));
        assert!(looks_like_prompt_path("checked-in.md"));
        assert!(!looks_like_prompt_path("inline prompt text"));
    }
}
