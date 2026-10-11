use super::*;

pub(super) fn validate_turn_limit(input: &Value, selection: &SastTaskSelection) -> Result<()> {
    anyhow::ensure!(
        input.get("agenticMaxModelTurns").is_none() || selection.run_agentic,
        "agenticMaxModelTurns requires the agentic task. Clear the option or select that task."
    );
    Ok(())
}

/// Translate the canonical parent option into the selected scanner's option.
pub(super) fn bind_turn_limit(input: &Value) -> Value {
    let mut child = input.clone();
    if let Some(limit) = child
        .as_object_mut()
        .and_then(|object| object.remove("agenticMaxModelTurns"))
    {
        child["maxModelTurns"] = limit;
    }
    child
}
