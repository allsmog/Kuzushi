use serde_json::Value;

pub(super) fn run_metadata_summary(value: &Value) -> Option<String> {
    require_run_metadata_shape(value)?;
    let run_id = string_field(value, &["runId", "run_id"])?;
    let status = string_field(value, &["status"])?;
    let mut parts = vec![format!("run {run_id}"), format!("status {status}")];
    parts.extend(duration_segment(value));
    parts.extend(tool_segment(value));
    parts.extend(findings_segment(value));
    parts.extend(model_segment(value));
    parts.extend(config_hash_segment(value));
    parts.extend(llm_calls_segment(value));
    parts.extend(cost_segment(value));
    parts.extend(reproducibility_count_segments(value));
    parts.extend(env_fingerprint_segment(value));
    parts.extend(target_git_segment(value));
    Some(parts.join(", "))
}

fn require_run_metadata_shape(value: &Value) -> Option<()> {
    value.get("kind")?;
    value.get("target")?;
    value_at(value, &["startedAtUnix", "started_at_unix"])?;
    Some(())
}

fn tool_segment(value: &Value) -> Option<String> {
    string_field(value, &["tool"]).map(|tool| format!("tool {tool}"))
}

fn duration_segment(value: &Value) -> Option<String> {
    let started = u64_field(value, &["startedAtUnix", "started_at_unix"])?;
    let completed = u64_field(value, &["completedAtUnix", "completed_at_unix"])?;
    Some(format!("duration {}s", completed.saturating_sub(started)))
}

fn findings_segment(value: &Value) -> Option<String> {
    value
        .get("findings")
        .and_then(Value::as_u64)
        .map(|findings| format!("findings {findings}"))
}

fn model_segment(value: &Value) -> Option<String> {
    string_field(value, &["model"]).map(|model| format!("model {model}"))
}

fn config_hash_segment(value: &Value) -> Option<String> {
    string_field(value, &["configHash", "config_hash"]).map(|hash| format!("config {hash}"))
}

fn llm_calls_segment(value: &Value) -> Option<String> {
    let count = value_at(value, &["llmCalls", "llm_calls"])
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    (count > 0).then(|| format!("llm calls {count}"))
}

fn cost_segment(value: &Value) -> Option<String> {
    value_at(value, &["costUsd", "cost_usd"])
        .and_then(Value::as_f64)
        .map(|cost| format!("cost ${cost:.6}"))
}

fn reproducibility_count_segments(value: &Value) -> Vec<String> {
    [
        ("house rules", &["houseRules", "house_rules"][..]),
        ("prompt overrides", &["promptOverrides", "prompt_overrides"][..]),
        ("cli args", &["cliArgs", "cli_args"][..]),
        ("scan args", &["scanArgs", "scan_args"][..]),
        ("loaded modules", &["loadedModules", "loaded_modules"][..]),
        (
            "module specifiers",
            &["loadedModuleSpecifiers", "loaded_module_specifiers"][..],
        ),
    ]
    .into_iter()
    .filter_map(|(label, keys)| metadata_array_count_segment(value, label, keys))
    .collect()
}

fn metadata_array_count_segment(value: &Value, label: &str, keys: &[&str]) -> Option<String> {
    array_len(value, keys)
        .filter(|count| *count > 0)
        .map(|count| format!("{label} {count}"))
}

fn env_fingerprint_segment(value: &Value) -> Option<String> {
    array_len(value, &["envFingerprint", "env_fingerprint"])
        .filter(|count| *count > 0)
        .map(|count| format!("env {count}"))
}

fn target_git_segment(value: &Value) -> Option<String> {
    let git = value_at(value, &["targetGit", "target_git"])?;
    let sha = string_field(git, &["sha"])?;
    let state = dirty_state(git);
    Some(format!("target git {sha} {state}"))
}

fn dirty_state(value: &Value) -> &'static str {
    match value.get("dirty").and_then(Value::as_bool) {
        Some(true) => "dirty",
        Some(false) => "clean",
        None => "unknown",
    }
}

fn array_len(value: &Value, keys: &[&str]) -> Option<usize> {
    value_at(value, keys).and_then(Value::as_array).map(Vec::len)
}

fn u64_field(object: &Value, keys: &[&str]) -> Option<u64> {
    value_at(object, keys).and_then(Value::as_u64)
}

fn string_field<'a>(object: &'a Value, keys: &[&str]) -> Option<&'a str> {
    value_at(object, keys)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn value_at<'a>(object: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}
