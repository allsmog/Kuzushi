use serde_json::Value;

pub(super) fn engine_line(input: &Value) -> String {
    if input["taskMode"] == "auto" {
        return "Engines: automatic selection; inspect per-engine outcomes after execution".into();
    }
    let engines = input["tasks"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|text| !text.is_empty());
    format!("Engines: {}", engines.as_deref().unwrap_or("not recorded"))
}

pub(super) fn semgrep_time_line(input: &Value) -> String {
    let selected = input["tasks"].as_array().is_some_and(|tasks| {
        tasks
            .iter()
            .any(|task| matches!(task.as_str(), Some("semgrep" | "semgrep:scan")))
    });
    if !selected && input["taskMode"] != "auto" {
        return String::new();
    }
    let milliseconds = input["semgrepTimeoutMs"]
        .as_u64()
        .unwrap_or(kuzushi_core::scan::DEFAULT_SEMGREP_JOB_TIMEOUT_MS);
    let jobs = input["semgrepJobs"].as_u64().unwrap_or(1);
    format!("Semgrep when selected: {milliseconds} ms per job for subprocess work across roots/batches. Source authentication is separate. Scan workers within each job: {jobs}.")
}

pub(super) fn scope_line(input: &Value) -> String {
    if let Some(scope) = saved_scope_line(input) {
        return scope;
    }
    if let Some(paths) = input["paths"].as_array().filter(|paths| !paths.is_empty()) {
        return format!(
            "Scope: {} selected path(s): {}",
            paths.len(),
            paths_preview(paths)
        );
    }
    "Scope: whole repository".into()
}

fn paths_preview(paths: &[Value]) -> String {
    let mut text = paths
        .iter()
        .take(3)
        .filter_map(Value::as_str)
        .map(|path| bounded_label(path))
        .collect::<Vec<_>>()
        .join(", ");
    if paths.len() > 3 {
        text.push_str("; further paths remain in the frozen inputs");
    }
    text
}

pub(super) fn bounded_label(label: &str) -> String {
    let mut chars = label.chars();
    let mut text = chars.by_ref().take(96).collect::<String>();
    if chars.next().is_some() {
        text.push('…');
    }
    text
}

fn saved_scope_line(input: &Value) -> Option<String> {
    if let Some(reference) = input.get("scanScopeRef").filter(|value| !value.is_null()) {
        return Some(reference["scopeId"].as_str().map_or_else(
            || "Scope: recorded boundary is unavailable; inspect the frozen inputs".into(),
            |id| format!("Scope: accepted boundary {id}"),
        ));
    }
    input["shard"]
        .as_str()
        .map(|shard| format!("Scope: selected shard {shard}"))
}

pub(super) fn context_line(input: &Value) -> String {
    format!(
        "Threat context: {}",
        crate::ui_view_models::study_config::context_reference_summary(input)
    )
}
