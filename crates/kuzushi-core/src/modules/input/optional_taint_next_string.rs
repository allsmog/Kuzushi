use super::*;

#[cfg(test)]
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

    let mut tasks = requested.unwrap_or_else(|| default_sast_tasks_for_disabled_filter(&disabled));

    if !disabled.is_empty() {
        tasks.retain(|task| {
            !disabled
                .iter()
                .any(|disabled| same_scan_task(task, disabled))
        });
    }
    Ok(tasks)
}

pub(in crate::modules) fn default_native_sast_tasks() -> Vec<String> {
    [
        "semgrep",
        "dep-hygiene",
        "cargo-audit",
        "secret-scan",
        "license-scan",
        "iac-scan",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_sast_tasks_for_disabled_filter(disabled: &[String]) -> Vec<String> {
    if disabled.is_empty() {
        return Vec::new();
    }
    default_native_sast_tasks()
}
