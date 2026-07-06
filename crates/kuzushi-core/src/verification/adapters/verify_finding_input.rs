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
    pub(in crate::verification::adapters) mcps: bool,
    pub(in crate::verification::adapters) mcp_tool_timeout_ms: Option<u64>,
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
        let mcps = parse_verify_mcps(input)?;
        let mcp_tool_timeout_ms = parse_mcp_tool_timeout_ms(input)?;

        Ok(Self {
            fingerprint,
            prompt_template,
            passes,
            mcps,
            mcp_tool_timeout_ms,
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

fn parse_verify_mcps(input: &Value) -> Result<bool> {
    match input.get("mcps") {
        None | Some(Value::Null) => Ok(true),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => anyhow::bail!("verify:finding mcps must be a boolean"),
    }
}

fn parse_mcp_tool_timeout_ms(input: &Value) -> Result<Option<u64>> {
    let raw = input
        .get("mcpToolTimeoutMs")
        .or_else(|| input.get("mcp_tool_timeout_ms"));
    match raw {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let timeout = value
                .as_u64()
                .context("verify:finding mcpToolTimeoutMs must be a positive integer")?;
            if timeout == 0 {
                anyhow::bail!("verify:finding mcpToolTimeoutMs must be at least 1");
            }
            Ok(Some(timeout))
        }
    }
}

const VERIFY_HEADER: &str = "You are Kuzushi's independent exploitability verifier. You did not discover this finding and \
must not assume it is real. Your job is adversarial falsification: try to disprove the claim \
by finding the mitigation, guard, validator, type constraint, privilege gate, or reachability \
barrier that makes it unexploitable.

Set exploitable=true only when you have traced attacker-controlled input to the sink with no \
blocking control in between. Set exploitable=false when evidence is incomplete, when attacker \
control is not established, when the path is unreachable, or when a cited guard defeats the \
claim.";

const VERIFY_INDEPENDENCE_RULES: &str = "Do not inherit confidence from discovery or triage. Do not rely on prior rationale. Inspect the \
claim and cited code independently.

If whitebox-static mode is active, do not generate PoCs, payloads, replay steps, fuzzing plans, \
or runtime exploitability claims. Return static verification only.";

pub(in crate::verification::adapters) fn verify_system_prompt() -> String {
    crate::prompts::assemble_system_prompt(
        VERIFY_HEADER,
        &[
            crate::prompts::FALSE_POSITIVE_TAXONOMY,
            crate::prompts::CONFIDENCE_CALIBRATION,
            VERIFY_INDEPENDENCE_RULES,
            crate::prompts::OUTPUT_CONTRACT,
        ],
    )
}

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
