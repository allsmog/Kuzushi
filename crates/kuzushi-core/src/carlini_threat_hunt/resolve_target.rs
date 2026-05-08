use super::prelude::*;
use super::*;

pub(crate) fn resolve_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(target) = optional_string(input, &["target"])? {
        let path = PathBuf::from(target);
        if path.is_absolute() {
            return Ok(path);
        }
        if let Some(workspace) = ctx.workspace {
            return Ok(workspace.root().join(path));
        }
        return Ok(std::env::current_dir()?.join(path));
    }
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    Ok(std::env::current_dir()?)
}
