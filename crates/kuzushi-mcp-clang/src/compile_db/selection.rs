use anyhow::{Context, Result};
use kuzushi_mcp_common::{
    compile_database::CompileDatabaseSnapshot, AuthorizedDirectory, ReadRootCapability,
};
use serde_json::Value;
use std::{path::Path, sync::Arc};

pub(crate) fn selected_snapshot(
    args: &Value,
    repo: &AuthorizedDirectory,
    capability: &ReadRootCapability,
) -> Result<Option<Arc<CompileDatabaseSnapshot>>> {
    let Some(value) = args.get("compileCommandsPath") else {
        return Ok(None);
    };
    let path = value
        .as_str()
        .filter(|value| !value.is_empty())
        .context("compileCommandsPath must be a nonempty path")?;
    let path = Path::new(path);
    let selected = if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo.path().join(path)
    };
    Ok(Some(Arc::new(CompileDatabaseSnapshot::capture(
        capability, &selected,
    )?)))
}
