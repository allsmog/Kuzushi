use super::prelude::*;
use super::*;

pub(crate) fn invariants_from_input(input: &Value) -> Option<Result<SystemsInvariantOutput>> {
    let value = input
        .get("invariants")
        .or_else(|| input.get("systemsInvariants"))
        .or_else(|| input.get("systems_invariants"))?;
    if value.get("invariants").is_some() {
        Some(serde_json::from_value(value.clone()).context("invalid systems invariants input"))
    } else {
        Some(
            serde_json::from_value(json!({ "invariants": value.clone() }))
                .context("invalid systems invariants input"),
        )
    }
}

pub(crate) fn require_json_object(value: Value) -> Result<Value> {
    if value.is_object() {
        Ok(value)
    } else {
        anyhow::bail!("systems-hunt structured output must be a JSON object")
    }
}

pub(crate) fn findings_schema() -> Value {
    json!({
        "type": "object",
        "required": ["findings"],
        "additionalProperties": true,
        "properties": {
            "findings": {"type": "array", "items": {"type": "object"}}
        }
    })
}

pub(crate) fn cwes_schema() -> Value {
    json!({
        "type": "object",
        "required": ["cwes"],
        "additionalProperties": true,
        "properties": {
            "cwes": {"type": "array", "items": {"type": "object"}}
        }
    })
}

pub(crate) fn invariants_schema() -> Value {
    json!({
        "type": "object",
        "required": ["invariants"],
        "additionalProperties": true,
        "properties": {
            "invariants": {"type": "array", "items": {"type": "object"}}
        }
    })
}

pub(crate) fn triggers_schema() -> Value {
    json!({
        "type": "object",
        "required": ["triggers"],
        "additionalProperties": true,
        "properties": {
            "triggers": {"type": "array", "items": {"type": "object"}}
        }
    })
}

pub(crate) fn resolve_model(
    label: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    options: &SystemsHuntInput,
) -> Result<String> {
    options
        .model
        .clone()
        .or_else(|| optional_nonempty_string(input, "MODEL").ok().flatten())
        .or_else(|| ctx.config.model.clone())
        .with_context(|| {
            format!("{label} requires an explicit model in config.toml, KUZUSHI_MODEL, or tool input; Kuzushi will not choose a fallback model")
        })
}

pub(crate) fn resolve_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(target) = input.get("target").and_then(Value::as_str) {
        let trimmed = target.trim();
        let path = if trimmed.is_empty() {
            std::env::current_dir().context("Could not resolve current directory")?
        } else {
            let candidate = PathBuf::from(trimmed);
            if candidate.is_absolute() {
                candidate
            } else {
                std::env::current_dir()
                    .context("Could not resolve current directory")?
                    .join(candidate)
            }
        };
        return Ok(path);
    }
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    std::env::current_dir().context("Could not resolve current directory")
}
