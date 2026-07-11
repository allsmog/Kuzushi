use super::*;

pub(crate) fn resolve_tool_target(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PathBuf> {
    if let Some(target) = input.get("target").and_then(Value::as_str) {
        return resolve_input_target(target, ctx);
    }
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    anyhow::bail!("taint-iris requires an explicit active workspace")
}

fn resolve_input_target(target: &str, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        anyhow::bail!("taint-iris target may not be blank")
    }
    let candidate = PathBuf::from(trimmed);
    resolve_candidate_target(candidate, ctx)
}

fn resolve_candidate_target(candidate: PathBuf, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if candidate.is_absolute() {
        Ok(candidate)
    } else {
        let workspace = ctx
            .workspace
            .context("taint-iris requires an explicit active workspace")?;
        Ok(workspace.root().join(candidate))
    }
}

pub(crate) fn optional_nonempty_string(input: &Value, key: &str) -> Result<Option<String>> {
    match input.get(key) {
        Some(Value::String(value)) => Ok(Some(value.trim().to_string()).filter(|s| !s.is_empty())),
        Some(_) => anyhow::bail!("pipeline:taint-cwe-select {key} must be a string"),
        None => Ok(None),
    }
}
