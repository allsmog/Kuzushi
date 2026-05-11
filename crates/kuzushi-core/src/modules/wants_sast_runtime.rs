use serde_json::Value;

pub fn wants_sast_runtime(input: &Value) -> bool {
    let whitebox_static = crate::whitebox_static_enabled(input).unwrap_or(false);
    triage_requested(input)
        || execution_requested(input, whitebox_static)
        || agentic_task_selected(input)
}

fn triage_requested(input: &Value) -> bool {
    bool_any(input, &["triage", "aiTriage", "ai_triage"])
}

fn execution_requested(input: &Value, whitebox_static: bool) -> bool {
    !whitebox_static && bool_any(input, &["verify", "autoPatch", "auto_patch"])
}

fn bool_any(input: &Value, keys: &[&str]) -> bool {
    keys.iter()
        .find_map(|key| input.get(*key))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn agentic_task_selected(input: &Value) -> bool {
    input
        .get("tasks")
        .and_then(Value::as_array)
        .is_some_and(|tasks| {
            tasks
                .iter()
                .filter_map(Value::as_str)
                .any(agentic_task_name)
        })
}

fn agentic_task_name(task: &str) -> bool {
    matches!(
        task.trim(),
        "agentic"
            | "agentic-sast"
            | "agentic-sast:scan"
            | "carlini"
            | "threat-hunt"
            | "carlini-threat-hunt"
            | "carlini-threat-hunt:run"
            | "taint"
            | "iris"
            | "taint-iris"
            | "taint-iris:hunt"
            | "taint-iris-next"
            | "iris-next"
            | "taint-next"
            | "taint-iris-next:hunt"
            | "systems"
            | "systems-hunt"
            | "systems-hunt:systems-hunt"
            | "deep-semantic"
            | "deep-semantic-hunt"
            | "systems-hunt:deep-semantic-hunt"
    )
}
