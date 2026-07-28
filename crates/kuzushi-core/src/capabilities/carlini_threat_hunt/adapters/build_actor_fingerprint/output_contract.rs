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

/// Per-item required keys are shared by the provider contract, actor prompt,
/// and deterministic normalizer. The normalizer still checks every item
/// because some providers return top-level structured JSON without enforcing
/// the nested item schema.
pub(in crate::capabilities::carlini_threat_hunt) fn findings_schema() -> Value {
    json!({
        "type": "object",
        "required": ["findings"],
        "additionalProperties": true,
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["title", "severity", "filePath", "startLine", "message"],
                    "additionalProperties": true,
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                        "filePath": {"type": "string", "description": "Target-relative source path of the vulnerable code"},
                        "startLine": {"type": "integer", "minimum": 1},
                        "endLine": {"type": "integer", "minimum": 1},
                        "ruleId": {"type": "string"},
                        "message": {"type": "string"},
                        "evidence": {"type": "string"},
                        "confidence": {"type": "string"},
                        "likelihood": {"type": "string"},
                        "impact": {"type": "string"},
                        "cwe": {"type": "array", "items": {"type": "string"}}
                    }
                }
            }
        }
    })
}
