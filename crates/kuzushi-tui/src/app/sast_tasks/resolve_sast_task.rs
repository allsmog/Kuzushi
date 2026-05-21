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
        "cargo audit" | "cargo-audit:scan" => "cargo-audit",
        "secret-scan:scan" | "secrets" => "secret-scan",
        "iac-scan:scan" => "iac-scan",
        "license" | "licenses" | "license-scan:scan" => "license-scan",
        "carlini"
        | "threat-hunt"
        | "carlini-threat-hunt"
        | "carlini-threat-hunt:run"
        | "offense-review:threat-hunt" => "offense-review",
        "taint" | "iris" | "taint-iris:hunt" => "taint-iris",
        "taint-next" | "iris-next" | "taint-iris-next:hunt" => "taint-iris-next",
        "systems" | "systems-hunt:systems-hunt" => "systems-hunt",
        other => other,
    };
    SAST_TASK_CAPABILITIES
        .iter()
        .find(|task| task.id == normalized || task.scan_task == normalized)
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
