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
    /// Model-turn budget for each agentic verifier pass; `None` keeps the
    /// bridge default.
    pub(in crate::verification::adapters) max_model_turns: Option<u32>,
    /// Optional cheap-tier plausibility gate: one pass with this model runs
    /// first, and only its REJECTION is trusted — it can kill obvious noise
    /// for a fraction of the cost, but an exploitable verdict always
    /// escalates to the configured full-strength passes.
    pub(in crate::verification::adapters) gate_model: Option<String>,
    /// Optional DIFFERENT tie-break model, consulted only when the panel
    /// splits evenly. A same-model or invalid spec is refused (disclosed, not
    /// substituted) and the split verdict stands. Unset means no escalation.
    pub(in crate::verification::adapters) escalation_model: Option<String>,
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
        let prompt_template = parse_prompt_template(input, cwd)?;
        let passes = parse_verify_passes(input)?;
        let mcps = parse_verify_mcps(input)?;
        let mcp_tool_timeout_ms = parse_mcp_tool_timeout_ms(input)?;
        let max_model_turns = crate::runtime::AgentRuntimeOptions::max_model_turns_from_input(
            input,
            "verify:finding",
        )?;
        let gate_model = parse_gate_model(input)?;
        let escalation_model = parse_escalation_model(input)?;

        Ok(Self {
            fingerprint,
            prompt_template,
            passes,
            mcps,
            mcp_tool_timeout_ms,
            max_model_turns,
            gate_model,
            escalation_model,
        })
    }
}

fn parse_prompt_template(input: &Value, cwd: &Path) -> Result<Option<String>> {
    Ok(match input.get("VERIFY_PROMPT") {
        Some(Value::String(value)) if !value.trim().is_empty() => {
            Some(crate::options::resolve_prepared_prompt_override_for_key(
                value.trim(),
                cwd,
                "VERIFY_PROMPT",
                crate::verification::DEFAULT_VERIFY_PROMPT,
            )?)
        }
        Some(Value::String(_)) | None => None,
        Some(_) => anyhow::bail!("verify:finding VERIFY_PROMPT must be a string"),
    })
}

/// The escalation model is stored raw (only trimmed), never validated here.
/// Validity is a disclosed tie-break decision, not a parse error: an invalid
/// spec is only ever consulted on a SPLIT panel, where `decide_tie_break`
/// returns `Refused(InvalidModelSpec)` and the split verdict stands with a
/// warning. Validating (and bailing) at parse time would instead hard-fail
/// EVERY verify:finding run — including single-pass, unanimous, and
/// gate-rejected runs that never escalate — which contradicts that contract.
fn parse_escalation_model(input: &Value) -> Result<Option<String>> {
    match input.get("escalationModel") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => {
            Ok(Some(value.trim().to_string()))
        }
        Some(_) => {
            anyhow::bail!("verify:finding escalationModel must be a non-empty model spec string")
        }
    }
}

fn parse_gate_model(input: &Value) -> Result<Option<String>> {
    match input.get("gateModel") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => {
            let model = value.trim().to_string();
            crate::runtime::validate_model_spec(&model)
                .context("verify:finding gateModel is not a valid model spec")?;
            Ok(Some(model))
        }
        Some(_) => anyhow::bail!("verify:finding gateModel must be a non-empty model spec string"),
    }
}

fn parse_verify_passes(input: &Value) -> Result<u32> {
    let raw = input.get("VERIFY_PASSES").or_else(|| input.get("passes"));
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

const VERIFY_HEADER: &str =
    "You are Kuzushi's independent exploitability verifier. You did not discover this finding and \
must not assume it is real. Your job is adversarial falsification: try to disprove the claim \
by finding the mitigation, guard, validator, type constraint, privilege gate, or reachability \
barrier that makes it unexploitable.

Set exploitable=true only when you have traced attacker-controlled input to the sink with no \
blocking control in between. Set exploitable=false only when cited evidence establishes that the path is unreachable or a guard defeats the claim. Set exploitable=null and proofVerdict=insufficient_finding_detail when evidence or attacker control is incomplete. Missing caller context is not evidence that a claim is false.";

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
    // `proofLevel`/`proofVerdict` are required downstream by the proof
    // snapshot (`verification_proof_snapshot`), which deliberately refuses to
    // default them — so the enforced schema must demand them from the model.
    json!({
        "type": "object",
        "required": ["fingerprint", "exploitable", "confidence", "proofLevel", "proofVerdict", "codeCitations"],
        "additionalProperties": true,
        "properties": {
            "fingerprint": {"type": "string"},
            "exploitable": {"type": ["boolean", "null"], "description": "true for a supported path, false for a claim defeated by cited evidence, null when evidence is incomplete or the language is unsupported"},
            "pocPayload": {"type": ["string", "null"]},
            "poc_payload": {"type": ["string", "null"]},
            "pocDescription": {"type": "string"},
            "poc_description": {"type": "string"},
            "attackVector": {"type": ["string", "null"]},
            "attack_vector": {"type": ["string", "null"]},
            "preconditions": {"type": "array", "items": {"type": "string"}},
            "confidence": {"type": "number"},
            "codeCitations": verification_citations_schema(),
            "proofLevel": {
                "type": "integer",
                "minimum": 1,
                "maximum": 3,
                "description": "Strength of the evidence behind this verdict: 1 = signal only, 2 = source-grounded static reasoning, 3 = corroborated static analysis (multiple independent code paths inspected), 4 = empirical runtime proof (never claim 4 from static review)."
            },
            "proofVerdict": {
                "type": "string",
                "enum": [
                    "exploited",
                    "not_reproduced",
                    "insufficient_finding_detail",
                    "language_unsupported_yet",
                    "inconclusive"
                ],
                "description": "Verdict of this review: `exploited` when the traced path stands with no blocking control, `not_reproduced` only when cited evidence defeats the claim, `insufficient_finding_detail` when the finding lacks the detail needed to judge it (exploitable=null); language_unsupported_yet also requires exploitable=null."
            }
        }
    })
}

fn verification_citations_schema() -> Value {
    json!({
        "type":"array", "maxItems":64,
        "description":"Decisive positives require source and sink roles; negatives require a control or reachability role. Use exact on-disk snippets. An empty array is inconclusive.",
        "items": {"type":"object", "required":["filePath","startLine","endLine","snippet","description","role"],
            "properties": {
                "filePath":{"type":"string"}, "startLine":{"type":"integer","minimum":1,"maximum":4294967295_u64},
                "endLine":{"type":"integer","minimum":1,"maximum":4294967295_u64},
                "snippet":{"type":"string","minLength":1}, "description":{"type":"string","minLength":1},
                "role":{"type":"string","enum":["source","sink","control","reachability"]}
            }
        }
    })
}

#[cfg(test)]
mod max_model_turns_tests {
    use crate::runtime::AgentRuntimeOptions;
    use serde_json::{json, Value};

    #[test]
    fn a_declared_turn_budget_is_bounded_and_absent_keeps_the_default() {
        let parse = |value: Value| {
            AgentRuntimeOptions::max_model_turns_from_input(&json!({ "maxModelTurns": value }), "t")
        };
        assert_eq!(parse(json!(24)).unwrap(), Some(24));
        let none = AgentRuntimeOptions::max_model_turns_from_input(&json!({}), "t");
        assert_eq!(none.unwrap(), None);
        let alias =
            AgentRuntimeOptions::max_model_turns_from_input(&json!({"max_model_turns": 5}), "t");
        assert_eq!(alias.unwrap(), Some(5));
        for invalid in [json!(0), json!(41), json!("12"), json!(-1)] {
            let error = parse(invalid).unwrap_err().to_string();
            assert!(error.contains("t maxModelTurns"), "{error}");
        }
    }
}
