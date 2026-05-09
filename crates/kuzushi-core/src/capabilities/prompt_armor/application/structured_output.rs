use anyhow::Result;
use serde_json::{json, Value};

pub(crate) fn require_json_object(value: Value) -> Result<Value> {
    if value.is_object() {
        Ok(value)
    } else {
        anyhow::bail!("prompt-armor structured output must be a JSON object")
    }
}

pub(crate) fn findings_schema() -> Value {
    json!({
        "type": "object",
        "required": ["findings"],
        "additionalProperties": true,
        "properties": {
            "summary": {"type": "string"},
            "findings": {"type": "array", "items": {"type": "object"}}
        }
    })
}
