use super::*;

pub(crate) fn variant_signature_schema() -> Value {
    let text = json!({"type":"string","minLength":1,"maxLength":4096});
    let list = json!({"type":"array","minItems":1,"maxItems":32,
        "items":{"type":"string","minLength":1,"maxLength":128}});
    json!({"type":"object","required":["source","sink","missingGuard","languages","keywords","description"],
        "properties":{"source":text,"sink":text,"missingGuard":text,"description":text,
            "languages":list,"keywords":list},"additionalProperties":true})
}

pub(crate) fn validate_variant_signature(value: Value) -> Result<Value> {
    let object = value
        .as_object()
        .context("Source pattern must be a JSON object")?;
    for key in ["source", "sink", "missingGuard", "description"] {
        let item = pattern_field(object, key);
        validate_pattern_text(item, key, 4096)?;
    }
    for key in ["languages", "keywords"] {
        validate_pattern_list(object.get(key), key)?;
    }
    Ok(value)
}

fn pattern_field<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    if key == "missingGuard" {
        return object.get(key).or_else(|| object.get("missing_guard"));
    }
    object.get(key)
}

fn validate_pattern_text(value: Option<&Value>, key: &str, limit: usize) -> Result<()> {
    let text = value
        .and_then(Value::as_str)
        .with_context(|| format!("Source pattern {key} must be text"))?;
    anyhow::ensure!(
        !text.trim().is_empty(),
        "Source pattern {key} must not be empty"
    );
    anyhow::ensure!(
        text.len() <= limit,
        "Source pattern {key} exceeds {limit} bytes"
    );
    Ok(())
}

fn validate_pattern_list(value: Option<&Value>, key: &str) -> Result<()> {
    let items = value
        .and_then(Value::as_array)
        .with_context(|| format!("Source pattern {key} must be a list"))?;
    anyhow::ensure!(
        (1..=32).contains(&items.len()),
        "Source pattern {key} must contain 1 to 32 items"
    );
    for item in items {
        validate_pattern_text(Some(item), key, 128)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
