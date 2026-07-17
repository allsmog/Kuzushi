use super::*;
use crate::workspace::WorkspaceTarget;

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
    crate::runtime::resolve_explicit_model(
        label,
        options
            .model
            .clone()
            .or_else(|| optional_nonempty_string(input, "MODEL").ok().flatten()),
        ctx.config.model.as_deref(),
    )
}

pub(crate) fn resolve_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    match input.get("target").and_then(Value::as_str) {
        Some(target) => resolve_explicit_target(target, ctx),
        None => resolve_context_target(ctx),
    }
}

fn resolve_explicit_target(target: &str, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        anyhow::bail!("systems-hunt target may not be blank")
    }
    resolve_target_candidate(PathBuf::from(trimmed), ctx)
}

fn resolve_target_candidate(candidate: PathBuf, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if candidate.is_absolute() {
        return Ok(candidate);
    }
    Ok(required_context_workspace(ctx)?.join(candidate))
}

fn resolve_context_target(ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    Ok(required_context_workspace(ctx)?.to_path_buf())
}

fn required_context_workspace<'a>(ctx: &'a ToolExecutionContext<'_>) -> Result<&'a Path> {
    ctx.workspace
        .map(WorkspaceTarget::root)
        .context("systems-hunt requires an explicit active workspace")
}
