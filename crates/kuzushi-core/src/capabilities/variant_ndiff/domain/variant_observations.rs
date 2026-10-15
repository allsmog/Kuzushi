use super::*;

pub(crate) fn validate_variant_observations(value: Value) -> Result<Value> {
    let rows = value.get("variants").and_then(Value::as_array).context(
        "Related observations must contain a variants array; an empty object is not a clean search",
    )?;
    for row in rows {
        validate_variant_observation(row)?;
    }
    Ok(value)
}

fn validate_variant_observation(value: &Value) -> Result<()> {
    let row = value
        .as_object()
        .context("Each related observation must be an object")?;
    require_observation_text(row, &["filePath", "file_path"], "file path")?;
    require_observation_text(row, &["severity"], "severity")?;
    require_observation_text(row, &["confidence"], "confidence")?;
    validate_observation_line(read_object_value(row, &["startLine", "start_line"]))
}

fn require_observation_text(row: &Map<String, Value>, keys: &[&str], label: &str) -> Result<()> {
    anyhow::ensure!(
        read_object_string(row, keys).is_some(),
        "Related observation requires nonblank {label}"
    );
    Ok(())
}

fn validate_observation_line(value: Option<&Value>) -> Result<()> {
    let Some(value) = value else { return Ok(()) };
    let line = value
        .as_u64()
        .context("Related observation line must be an integer")?;
    anyhow::ensure!(
        (1..=u64::from(u32::MAX)).contains(&line),
        "Related observation line must fit a positive source line"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
