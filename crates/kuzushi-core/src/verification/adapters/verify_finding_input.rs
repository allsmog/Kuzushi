use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;

#[derive(Debug, Clone)]
pub(in crate::verification::adapters) struct VerifyFindingInput {
    pub(in crate::verification::adapters) fingerprint: String,
    pub(in crate::verification::adapters) prompt_template: Option<String>,
}

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

        Ok(Self {
            fingerprint,
            prompt_template,
        })
    }
}

pub(in crate::verification::adapters) const VERIFY_SYSTEM_PROMPT: &str = r#"You are Kuzushi's exploitability verification agent.
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
