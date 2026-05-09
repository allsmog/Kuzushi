use super::*;

pub(in crate::capabilities::carlini_threat_hunt) fn optional_string(
    input: &Value,
    keys: &[&str],
) -> Result<Option<String>> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return match value {
                Value::String(text) => {
                    Ok(Some(text.trim().to_string()).filter(|text| !text.is_empty()))
                }
                _ => anyhow::bail!("carlini-threat-hunt:run {key} must be a string"),
            };
        }
    }
    Ok(None)
}

pub(in crate::capabilities::carlini_threat_hunt) fn read_usize(
    input: &Value,
    keys: &[&str],
    fallback: usize,
    min: usize,
) -> usize {
    for key in keys {
        if let Some(value) = input.get(*key) {
            let parsed = match value {
                Value::Number(number) => number.as_u64().map(|value| value as usize),
                Value::String(text) => text.parse::<usize>().ok(),
                _ => None,
            };
            return parsed.filter(|value| *value >= min).unwrap_or(fallback);
        }
    }
    fallback
}

pub(in crate::capabilities::carlini_threat_hunt) fn bool_input(
    input: &Value,
    keys: &[&str],
    fallback: bool,
) -> bool {
    keys.iter()
        .find_map(|key| input.get(*key).and_then(Value::as_bool))
        .unwrap_or(fallback)
}

pub(in crate::capabilities::carlini_threat_hunt) fn resolve_prompt_override(
    value: &str,
    cwd: &Path,
) -> Result<String> {
    crate::options::resolve_prompt_override_for_key(value, cwd, "CARLINI_THREAT_HUNT_PROMPT")
}
