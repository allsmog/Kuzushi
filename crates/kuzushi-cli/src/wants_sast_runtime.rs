use super::prelude::*;
use super::*;

pub(crate) fn wants_sast_runtime(input: &serde_json::Value) -> bool {
    let whitebox_static = kuzushi_core::whitebox_static_enabled(input).unwrap_or(false);
    let triage_runtime = input
        .get("triage")
        .or_else(|| input.get("aiTriage"))
        .or_else(|| input.get("ai_triage"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let execution_runtime = !whitebox_static
        && input
            .get("verify")
            .or_else(|| input.get("autoPatch"))
            .or_else(|| input.get("auto_patch"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

    triage_runtime
        || execution_runtime
        || input
            .get("tasks")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|tasks| {
                tasks
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .any(|task| {
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
                    })
            })
}
