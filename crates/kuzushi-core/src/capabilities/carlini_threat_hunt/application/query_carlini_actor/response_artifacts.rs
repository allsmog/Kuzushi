use super::CarliniDebugArtifacts;
use crate::runtime::AgentQueryResponse;
use crate::structured_output::{balanced_json_slices, ensure_response_material_budget};
use serde_json::{json, Value};

pub(crate) fn extract_carlini_findings_response(response: &AgentQueryResponse) -> Option<Value> {
    ensure_response_material_budget(response).ok()?;
    if let Some(structured) = response.structured.as_ref() {
        if is_carlini_findings_object(structured) {
            return Some(structured.clone());
        }
    }

    balanced_json_slices(&response.text)
        .ok()?
        .into_iter()
        .find_map(|candidate| {
            let value = serde_json::from_str::<Value>(candidate).ok()?;
            is_carlini_findings_object(&value).then_some(value)
        })
}

pub(super) fn write_carlini_actor_prompt_artifact(
    debug_artifacts: Option<&CarliniDebugArtifacts>,
    actor_fingerprint: &str,
    prompt: &str,
) {
    write_carlini_actor_artifact(
        debug_artifacts,
        actor_fingerprint,
        "prompt",
        &json!({ "actorFingerprint": actor_fingerprint, "prompt": prompt }),
    );
}

pub(super) fn write_carlini_actor_repair_prompt_artifact(
    debug_artifacts: Option<&CarliniDebugArtifacts>,
    actor_fingerprint: &str,
    prompt: &str,
) {
    write_carlini_actor_artifact(
        debug_artifacts,
        actor_fingerprint,
        "repair-prompt",
        &json!({ "actorFingerprint": actor_fingerprint, "prompt": prompt }),
    );
}

pub(super) fn write_carlini_actor_response_artifact(
    debug_artifacts: Option<&CarliniDebugArtifacts>,
    actor_fingerprint: &str,
    phase: &str,
    response: &AgentQueryResponse,
) {
    write_carlini_actor_artifact(
        debug_artifacts,
        actor_fingerprint,
        phase,
        &carlini_actor_response_artifact_payload(actor_fingerprint, phase, response),
    );
}

pub(crate) fn carlini_actor_response_artifact_payload(
    actor_fingerprint: &str,
    phase: &str,
    response: &AgentQueryResponse,
) -> Value {
    let mut payload = json!({
        "actorFingerprint": actor_fingerprint,
        "phase": phase,
        "text": response.text,
        "structured": response.structured,
        "ignoredToolPrelude": ignored_tool_prelude_summary(response),
        "estimatedCostUsd": response.estimated_cost_usd,
        "inputTokens": response.input_tokens,
        "outputTokens": response.output_tokens,
        "promptCache": response.prompt_cache,
        "truncated": response.truncated,
        "stopReason": response.stop_reason,
    });
    let cost = response
        .checked_cost_report()
        .expect("Carlini response artifact cost was checked by the runtime boundary");
    crate::module_result::apply_runtime_cost_report(&mut payload, cost);
    payload
}

fn ignored_tool_prelude_summary(response: &AgentQueryResponse) -> Value {
    if ensure_response_material_budget(response).is_err() {
        return json!({
            "present": false,
            "count": 0,
            "reason": "Carlini response material exceeded the structured-output inspection budget; tool-shaped JSON was not inspected or executed.",
            "objects": [],
        });
    }
    let preludes = ignored_tool_prelude_objects(&response.text);
    json!({
        "present": !preludes.is_empty(),
        "count": preludes.len(),
        "reason": "Carlini threat hunt is a prompt-only query path; tool-shaped JSON in model text was ignored and was not executed.",
        "objects": preludes,
    })
}

fn ignored_tool_prelude_objects(text: &str) -> Vec<Value> {
    let Ok(slices) = balanced_json_slices(text) else {
        return Vec::new();
    };
    let older_candidates_start = slices
        .iter()
        .position(|candidate| {
            serde_json::from_str::<Value>(candidate)
                .ok()
                .is_some_and(|value| is_carlini_findings_object(&value))
        })
        .map_or(0, |index| index + 1);

    slices
        .into_iter()
        .skip(older_candidates_start)
        .rev()
        .filter_map(|candidate| serde_json::from_str::<Value>(candidate).ok())
        .filter(is_tool_shaped_json)
        .collect()
}

fn is_carlini_findings_object(value: &Value) -> bool {
    value
        .get("findings")
        .is_some_and(|findings| findings.is_array())
}

fn is_tool_shaped_json(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.contains_key("cmd")
        || object.contains_key("tool")
        || object.contains_key("tool_call")
        || object.contains_key("toolCall")
        || (object.contains_key("name") && object.contains_key("arguments"))
}

fn write_carlini_actor_artifact(
    debug_artifacts: Option<&CarliniDebugArtifacts>,
    actor_fingerprint: &str,
    phase: &str,
    value: &Value,
) {
    let Some(debug_artifacts) = debug_artifacts else {
        return;
    };
    let leaf = format!(
        "carlini-threat-hunt/{}-{}.json",
        sanitize_actor_artifact_leaf(actor_fingerprint),
        phase
    );
    let _ = crate::run_artifacts::write_run_artifact_json(
        &debug_artifacts.target,
        &debug_artifacts.run_id,
        &leaf,
        format!("carlini {phase}"),
        value,
    );
}

fn sanitize_actor_artifact_leaf(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}
