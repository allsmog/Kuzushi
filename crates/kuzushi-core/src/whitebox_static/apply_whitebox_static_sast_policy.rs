use super::prelude::*;
use super::*;
use serde_json::Map;

pub(in crate::whitebox_static) fn normalize_agent_tool_name(tool: &str) -> String {
    tool.chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .flat_map(char::to_lowercase)
        .collect()
}

pub fn apply_whitebox_static_sast_policy(
    input: Value,
) -> Result<(Value, Option<WhiteboxStaticPolicy>)> {
    let mode = analysis_mode_from_input(&input)?;
    if mode != AnalysisMode::WhiteboxStatic {
        return Ok((input, None));
    }

    let mut object = input
        .as_object()
        .cloned()
        .context("sast:scan input must be a JSON object")?;
    let mut disabled = Vec::new();
    force_false(&mut object, &mut disabled, "verify");
    force_false(&mut object, &mut disabled, "autoPatch");
    force_false(&mut object, &mut disabled, "auto_patch");
    force_false(&mut object, &mut disabled, "patch");
    force_false(&mut object, &mut disabled, "patching");
    force_false(&mut object, &mut disabled, "poc");
    force_false(&mut object, &mut disabled, "pocHarness");
    force_false(&mut object, &mut disabled, "poc_harness");
    force_false(&mut object, &mut disabled, "pocExecution");
    force_false(&mut object, &mut disabled, "poc_execution");
    force_false(&mut object, &mut disabled, "dynamicAnalysis");
    force_false(&mut object, &mut disabled, "dynamic_analysis");
    force_false(&mut object, &mut disabled, "cryptoBehavioralTesting");
    force_false(&mut object, &mut disabled, "crypto_behavioral_testing");
    force_false(&mut object, &mut disabled, "runtimeExploitabilityClaims");
    force_false(&mut object, &mut disabled, "runtime_exploitability_claims");
    force_false(&mut object, &mut disabled, "executionProofStates");
    force_false(&mut object, &mut disabled, "execution_proof_states");

    rewrite_execution_proof_state(&mut object, &mut disabled, "proofState");
    rewrite_execution_proof_state(&mut object, &mut disabled, "proof_state");
    rewrite_execution_proof_states(&mut object, &mut disabled, "proofStates");
    rewrite_execution_proof_states(&mut object, &mut disabled, "proof_states");

    object.insert(
        "mode".to_string(),
        Value::String(AnalysisMode::WhiteboxStatic.as_str().to_string()),
    );
    object.insert(
        "whiteboxStatic".to_string(),
        WhiteboxStaticPolicy::active(disabled.clone()).to_json(),
    );

    Ok((
        Value::Object(object),
        Some(WhiteboxStaticPolicy::active(disabled)),
    ))
}

pub(in crate::whitebox_static) fn force_false(
    object: &mut Map<String, Value>,
    disabled: &mut Vec<String>,
    key: &str,
) {
    let was_enabled = object.get(key).and_then(Value::as_bool).unwrap_or(false);
    object.insert(key.to_string(), Value::Bool(false));
    if was_enabled {
        disabled.push(key.to_string());
    }
}

pub(in crate::whitebox_static) fn rewrite_execution_proof_state(
    object: &mut Map<String, Value>,
    disabled: &mut Vec<String>,
    key: &str,
) {
    if object
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(is_execution_proof_state)
    {
        object.insert(
            key.to_string(),
            Value::String("needs_runtime_evidence".to_string()),
        );
        disabled.push(key.to_string());
    }
}

pub(in crate::whitebox_static) fn rewrite_execution_proof_states(
    object: &mut Map<String, Value>,
    disabled: &mut Vec<String>,
    key: &str,
) {
    let Some(values) = object.get(key).and_then(Value::as_array) else {
        return;
    };
    if !values
        .iter()
        .filter_map(Value::as_str)
        .any(is_execution_proof_state)
    {
        return;
    }
    object.insert(
        key.to_string(),
        Value::Array(vec![Value::String("needs_runtime_evidence".to_string())]),
    );
    disabled.push(key.to_string());
}

pub(in crate::whitebox_static) fn is_execution_proof_state(value: &str) -> bool {
    matches!(
        value.trim(),
        "execution_confirmed"
            | "runtime_confirmed"
            | "dynamic_confirmed"
            | "exploit_confirmed"
            | "poc_confirmed"
    )
}

pub(in crate::whitebox_static) fn truthy_bool(input: &Value, keys: &[&str]) -> Result<bool> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            if let Some(enabled) = value.get("enabled").and_then(Value::as_bool) {
                return Ok(enabled);
            }
            return value
                .as_bool()
                .with_context(|| format!("{key} must be a boolean"));
        }
    }
    Ok(false)
}
