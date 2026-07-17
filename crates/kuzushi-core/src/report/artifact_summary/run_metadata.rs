use serde_json::Value;

pub(super) fn run_metadata_summary(value: &Value) -> Option<String> {
    require_run_metadata_shape(value)?;
    let run_id = string_field(value, "runId")?;
    let status = string_field(value, "status")?;
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
    value.get("startedAtUnix")?;
    Some(())
}

fn tool_segment(value: &Value) -> Option<String> {
    string_field(value, "tool").map(|tool| format!("tool {tool}"))
}

fn duration_segment(value: &Value) -> Option<String> {
    let started = u64_field(value, "startedAtUnix")?;
    let completed = u64_field(value, "completedAtUnix")?;
    Some(format!("duration {}s", completed.saturating_sub(started)))
}

fn findings_segment(value: &Value) -> Option<String> {
    value
        .get("findings")
        .and_then(Value::as_u64)
        .map(|findings| format!("findings {findings}"))
}

fn model_segment(value: &Value) -> Option<String> {
    string_field(value, "model").map(|model| format!("model {model}"))
}

fn config_hash_segment(value: &Value) -> Option<String> {
    string_field(value, "configHash").map(|hash| format!("config {hash}"))
}

fn llm_calls_segment(value: &Value) -> Option<String> {
    let count = value
        .get("llmCalls")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    (count > 0).then(|| format!("llm calls {count}"))
}

fn cost_segment(value: &Value) -> Option<String> {
    if let Some(cost) = value.get("costUsd").and_then(Value::as_f64) {
        return Some(format!("cost ${cost:.6}"));
    }
    let observed = value.get("observedCostUsd").and_then(Value::as_f64)?;
    (value
        .get("providerSpendUnresolved")
        .and_then(Value::as_bool)
        == Some(true))
    .then(|| format!("observed cost ${observed:.6}, provider spend unresolved"))
}

fn reproducibility_count_segments(value: &Value) -> Vec<String> {
    [
        ("house rules", "houseRules"),
        ("prompt overrides", "promptOverrides"),
        ("cli args", "cliArgs"),
        ("loaded modules", "loadedModules"),
    ]
    .into_iter()
    .filter_map(|(label, key)| metadata_array_count_segment(value, label, key))
    .collect()
}

fn metadata_array_count_segment(value: &Value, label: &str, key: &str) -> Option<String> {
    array_len(value, key)
        .filter(|count| *count > 0)
        .map(|count| format!("{label} {count}"))
}

fn env_fingerprint_segment(value: &Value) -> Option<String> {
    array_len(value, "envFingerprint")
        .filter(|count| *count > 0)
        .map(|count| format!("env {count}"))
}

fn target_git_segment(value: &Value) -> Option<String> {
    let git = value.get("targetGit")?;
    let sha = string_field(git, "sha")?;
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

fn array_len(value: &Value, key: &str) -> Option<usize> {
    value.get(key).and_then(Value::as_array).map(Vec::len)
}

fn u64_field(object: &Value, key: &str) -> Option<u64> {
    object.get(key).and_then(Value::as_u64)
}

fn string_field<'a>(object: &'a Value, key: &str) -> Option<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}
