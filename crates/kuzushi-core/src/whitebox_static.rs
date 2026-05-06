use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AnalysisMode {
    Standard,
    WhiteboxStatic,
}

impl AnalysisMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::WhiteboxStatic => "whitebox-static",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxStaticPolicy {
    pub enabled: bool,
    pub mode: String,
    pub verify: bool,
    pub poc_harness: bool,
    pub poc_execution: bool,
    pub dynamic_analysis: bool,
    pub crypto_behavioral_testing: bool,
    pub patching: bool,
    pub auto_patch: bool,
    pub execution_proof_states: bool,
    pub runtime_exploitability_claims: bool,
    pub disabled: Vec<String>,
}

impl WhiteboxStaticPolicy {
    fn active(disabled: Vec<String>) -> Self {
        Self {
            enabled: true,
            mode: AnalysisMode::WhiteboxStatic.as_str().to_string(),
            verify: false,
            poc_harness: false,
            poc_execution: false,
            dynamic_analysis: false,
            crypto_behavioral_testing: false,
            patching: false,
            auto_patch: false,
            execution_proof_states: false,
            runtime_exploitability_claims: false,
            disabled,
        }
    }

    pub fn to_json(&self) -> Value {
        json!(self)
    }
}

pub fn analysis_mode_from_input(input: &Value) -> Result<AnalysisMode> {
    if truthy_bool(input, &["whiteboxStatic", "whitebox_static"])? {
        return Ok(AnalysisMode::WhiteboxStatic);
    }

    let raw = input
        .get("mode")
        .or_else(|| input.get("preset"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("standard");
    match raw {
        "standard" | "default" | "sast" => Ok(AnalysisMode::Standard),
        "whitebox-static" => Ok(AnalysisMode::WhiteboxStatic),
        other => anyhow::bail!(
            "analysis mode {other:?} is unsupported; valid modes: standard, whitebox-static"
        ),
    }
}

pub fn whitebox_static_enabled(input: &Value) -> Result<bool> {
    Ok(analysis_mode_from_input(input)? == AnalysisMode::WhiteboxStatic)
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

fn force_false(object: &mut Map<String, Value>, disabled: &mut Vec<String>, key: &str) {
    let was_enabled = object.get(key).and_then(Value::as_bool).unwrap_or(false);
    object.insert(key.to_string(), Value::Bool(false));
    if was_enabled {
        disabled.push(key.to_string());
    }
}

fn rewrite_execution_proof_state(
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

fn rewrite_execution_proof_states(
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

fn is_execution_proof_state(value: &str) -> bool {
    matches!(
        value.trim(),
        "execution_confirmed"
            | "runtime_confirmed"
            | "dynamic_confirmed"
            | "exploit_confirmed"
            | "poc_confirmed"
    )
}

fn truthy_bool(input: &Value, keys: &[&str]) -> Result<bool> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return value
                .as_bool()
                .with_context(|| format!("{key} must be a boolean"));
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitebox_static_policy_disables_execution_features_and_proof_states() {
        let (sanitized, policy) = apply_whitebox_static_sast_policy(json!({
            "mode": "whitebox-static",
            "verify": true,
            "autoPatch": true,
            "pocHarness": true,
            "pocExecution": true,
            "dynamicAnalysis": true,
            "cryptoBehavioralTesting": true,
            "patching": true,
            "proofState": "execution_confirmed",
            "proofStates": ["signal_only", "runtime_confirmed"]
        }))
        .unwrap();
        let policy = policy.unwrap();

        assert!(policy.enabled);
        assert!(!policy.verify);
        assert!(!policy.poc_harness);
        assert!(!policy.poc_execution);
        assert!(!policy.dynamic_analysis);
        assert!(!policy.crypto_behavioral_testing);
        assert!(!policy.patching);
        assert!(!policy.auto_patch);
        assert!(!policy.execution_proof_states);
        assert!(!policy.runtime_exploitability_claims);
        assert_eq!(sanitized["verify"], json!(false));
        assert_eq!(sanitized["autoPatch"], json!(false));
        assert_eq!(sanitized["proofState"], json!("needs_runtime_evidence"));
        assert_eq!(sanitized["proofStates"], json!(["needs_runtime_evidence"]));
        assert!(!serde_json::to_string(&sanitized)
            .unwrap()
            .contains("execution_confirmed"));
    }

    #[test]
    fn standard_mode_preserves_input() {
        let input = json!({"mode": "standard", "verify": true});
        let (sanitized, policy) = apply_whitebox_static_sast_policy(input.clone()).unwrap();

        assert_eq!(sanitized, input);
        assert!(policy.is_none());
    }
}
