use super::prelude::*;
use super::*;

pub(in crate::modules) fn optional_taint_next_string(
    input: &Value,
    keys: &[&str],
) -> Result<Option<String>> {
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

pub(in crate::modules) fn positive_usize_input(
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

pub(in crate::modules) fn positive_f64_input(
    input: &Value,
    keys: &[&str],
    label: &str,
) -> Result<Option<f64>> {
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

pub(in crate::modules) fn parse_sast_tasks(input: &Value) -> Result<Vec<String>> {
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
