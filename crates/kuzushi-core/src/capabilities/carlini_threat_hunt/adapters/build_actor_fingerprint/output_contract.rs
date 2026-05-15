use super::*;

pub(in crate::capabilities::carlini_threat_hunt) fn require_json_object(
    value: Value,
) -> Result<Value> {
    if !value.is_object() {
        anyhow::bail!("carlini-threat-hunt structured output must be a JSON object");
    }
    match value.get("findings") {
        Some(Value::Array(_)) => Ok(value),
        Some(_) => anyhow::bail!("carlini-threat-hunt `findings` field must be an array"),
        None => anyhow::bail!("carlini-threat-hunt structured output must contain `findings`"),
    }
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
