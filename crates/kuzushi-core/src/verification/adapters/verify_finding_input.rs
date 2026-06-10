use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::Path;

#[derive(Debug, Clone)]
pub(in crate::verification::adapters) struct VerifyFindingInput {
    pub(in crate::verification::adapters) fingerprint: String,
    pub(in crate::verification::adapters) prompt_template: Option<String>,
    /// Number of independent verifier passes to run and combine by
    /// consensus. Defaults to 1 (single pass). Raising it trades model
    /// spend for precision: a finding is only confirmed exploitable when
    /// a strict majority of independent adversarial verifiers agree.
    pub(in crate::verification::adapters) passes: u32,
}

/// Upper bound on independent verifier passes. Beyond this the marginal
/// precision gain does not justify the linear model spend.
const MAX_VERIFY_PASSES: u64 = 7;

impl VerifyFindingInput {
    pub(in crate::verification::adapters) fn from_tool_input(
        input: &Value,
        cwd: &Path,
    ) -> Result<Self> {
        let fingerprint = match input.get("fingerprint") {
            Some(Value::String(value)) if !value.trim().is_empty() => value.trim().to_string(),
            Some(_) => anyhow::bail!("verify:finding fingerprint must be a non-empty string"),
            None => anyhow::bail!("verify:finding requires a fingerprint"),
        };
        let prompt_template = match input.get("VERIFY_PROMPT") {
            Some(Value::String(value)) if !value.trim().is_empty() => {
                Some(crate::options::resolve_prompt_override_for_key(
                    value.trim(),
                    cwd,
                    "VERIFY_PROMPT",
                )?)
            }
            Some(Value::String(_)) | None => None,
            Some(_) => anyhow::bail!("verify:finding VERIFY_PROMPT must be a string"),
        };
        let passes = parse_verify_passes(input)?;

        Ok(Self {
            fingerprint,
            prompt_template,
            passes,
        })
    }
}

fn parse_verify_passes(input: &Value) -> Result<u32> {
    let raw = input
        .get("VERIFY_PASSES")
        .or_else(|| input.get("passes"));
    let passes = match raw {
        None | Some(Value::Null) => 1,
        Some(value) => value
            .as_u64()
            .context("verify:finding VERIFY_PASSES must be a positive integer")?,
    };
    if passes == 0 {
        anyhow::bail!("verify:finding VERIFY_PASSES must be at least 1");
    }
    Ok(passes.min(MAX_VERIFY_PASSES) as u32)
}

pub(in crate::verification::adapters) const VERIFY_SYSTEM_PROMPT: &str = r#"You are Kuzushi's independent exploitability verifier. You did not discover this finding and must not assume it is real. Your job is to disprove it: assume it is a false positive and find the mitigation that makes it unexploitable. Inspect the actual code rather than trusting the claim. Set exploitable=true only when you have traced attacker-controlled input to the sink with no blocking control (validation, sanitization, auth gate, type constraint, unreachable path) in between; otherwise set exploitable=false. Be conservative — incomplete runtime evidence means exploitable=false.
Return only JSON with these fields:
{"fingerprint":"...","exploitable":true|false,"poc_payload":string|null,"poc_description":"...","attack_vector":string|null,"preconditions":["..."],"confidence":0.0-1.0}."#;

pub(in crate::verification::adapters) fn verification_result_schema() -> Value {
    json!({
        "type": "object",
        "required": ["fingerprint", "exploitable", "confidence"],
        "additionalProperties": true,
        "properties": {
            "fingerprint": {"type": "string"},
            "exploitable": {"type": "boolean"},
            "pocPayload": {"type": ["string", "null"]},
            "poc_payload": {"type": ["string", "null"]},
            "pocDescription": {"type": "string"},
            "poc_description": {"type": "string"},
            "attackVector": {"type": ["string", "null"]},
            "attack_vector": {"type": ["string", "null"]},
            "preconditions": {"type": "array", "items": {"type": "string"}},
            "confidence": {"type": "number"}
        }
    })
}
