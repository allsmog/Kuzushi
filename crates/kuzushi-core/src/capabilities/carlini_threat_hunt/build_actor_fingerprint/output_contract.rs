use super::*;

pub(in crate::capabilities::carlini_threat_hunt) fn require_json_object(
    value: Value,
) -> Result<Value> {
    if value.is_object() {
        return Ok(value);
    }
    anyhow::bail!("carlini-threat-hunt structured output must be a JSON object")
}

pub(in crate::capabilities::carlini_threat_hunt) fn findings_schema() -> Value {
    json!({
        "type": "object",
        "required": ["findings"],
        "additionalProperties": true,
        "properties": {
            "findings": {"type": "array", "items": {"type": "object"}}
        }
    })
}
