use super::*;

pub(crate) fn resolve_tool_target(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PathBuf> {
    if let Some(target) = input.get("target").and_then(Value::as_str) {
        return resolve_input_target(target);
    }
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    current_dir()
}

fn resolve_input_target(target: &str) -> Result<PathBuf> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return current_dir();
    }
    let candidate = PathBuf::from(trimmed);
    resolve_candidate_target(candidate)
}

fn resolve_candidate_target(candidate: PathBuf) -> Result<PathBuf> {
    if candidate.is_absolute() {
        Ok(candidate)
    } else {
        Ok(current_dir()?.join(candidate))
    }
}

fn current_dir() -> Result<PathBuf> {
    std::env::current_dir().context("Could not resolve current directory")
}

pub(crate) fn optional_nonempty_string(input: &Value, key: &str) -> Result<Option<String>> {
    match input.get(key) {
        Some(Value::String(value)) => Ok(Some(value.trim().to_string()).filter(|s| !s.is_empty())),
        Some(_) => anyhow::bail!("pipeline:taint-cwe-select {key} must be a string"),
        None => Ok(None),
    }
}
