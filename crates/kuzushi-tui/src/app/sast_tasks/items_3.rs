use super::prelude::*;
use super::*;

pub(crate) fn resolve_sast_task(raw_id: &str) -> Option<&'static SastTaskCapability> {
    let normalized = raw_id.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    let normalized = match normalized.as_str() {
        "agentic-sast" | "agentic-sast:scan" => "agentic",
        "semgrep:scan" => "semgrep",
        "codeql:scan" => "codeql",
        "dep-hygiene:check" => "dep-hygiene",
        "secret-scan:scan" | "secrets" => "secret-scan",
        "iac-scan:scan" => "iac-scan",
        "carlini" | "threat-hunt" | "carlini-threat-hunt:run" => "carlini-threat-hunt",
        "taint" | "iris" | "taint-iris:hunt" => "taint-iris",
        "taint-next" | "iris-next" | "taint-iris-next:hunt" => "taint-iris-next",
        "systems" | "systems-hunt:systems-hunt" => "systems-hunt",
        other => other,
    };
    SAST_TASK_CAPABILITIES
        .iter()
        .find(|task| task.id == normalized || task.scan_task == normalized)
}

pub(crate) fn parse_native_scan_tasks(input: &serde_json::Value) -> Result<Option<Vec<String>>> {
    let mode = input
        .get("taskMode")
        .or_else(|| input.get("task_mode"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("auto");
    if !matches!(mode, "auto" | "manual") {
        anyhow::bail!("scan taskMode must be auto or manual");
    }

    let requested = read_task_list_value(input.get("tasks"));
    let disabled = read_task_list_value(
        input
            .get("disabledTasks")
            .or_else(|| input.get("disabled_tasks")),
    );
    let disabled = disabled
        .iter()
        .filter_map(|task| resolve_sast_task(task).map(|task| task.id))
        .collect::<BTreeSet<_>>();

    let selected = if !requested.is_empty() {
        requested
    } else if !disabled.is_empty() {
        SAST_TASK_CAPABILITIES
            .iter()
            .filter(|task| task.default_enabled && !disabled.contains(task.id))
            .map(|task| task.id.to_string())
            .collect()
    } else {
        Vec::new()
    };

    if mode == "manual" && selected.is_empty() {
        anyhow::bail!("scan taskMode=manual requires at least one task. Next: /task mode auto");
    }
    if selected.is_empty() {
        return Ok(None);
    }

    let mut native_tasks = Vec::new();
    let mut unsupported = Vec::new();
    for raw in selected {
        let Some(task) = resolve_sast_task(&raw) else {
            anyhow::bail!("{}", unknown_sast_task_message(&raw));
        };
        if task.native_scan {
            native_tasks.push(task.scan_task.to_string());
        } else {
            unsupported.push(task.id);
        }
    }
    if !unsupported.is_empty() {
        anyhow::bail!(
            "scan supports native tasks only; unsupported here: {}. Next: run sast:scan",
            unsupported.join(", ")
        );
    }
    if native_tasks.is_empty() {
        anyhow::bail!("scan selected no native tasks. Next: /tasks or run sast:scan");
    }

    Ok(Some(native_tasks))
}

pub(crate) fn read_task_list_value(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::String(value)) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
        _ => Vec::new(),
    }
}
