use super::*;

pub(crate) fn resolve_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    match optional_string(input, &["target"])? {
        Some(target) => resolve_explicit_target(target, ctx),
        None => resolve_default_target(ctx),
    }
}

fn resolve_explicit_target(target: String, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let path = PathBuf::from(target);
    if path.is_absolute() {
        return Ok(path);
    }
    resolve_relative_target(path, ctx)
}

fn resolve_relative_target(path: PathBuf, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    Ok(target_base_dir(ctx)?.join(path))
}

fn target_base_dir(ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    ctx.workspace
        .map(|workspace| workspace.root().to_path_buf())
        .context("carlini threat hunt requires an explicit active workspace")
}

fn resolve_default_target(ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    target_base_dir(ctx)
}
