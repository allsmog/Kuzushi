use anyhow::{Context, Result};
use kuzushi_mcp_common::{compile_database::CompileDatabaseSnapshot, ReadRootCapability};
use std::path::Path;

pub(super) fn capture(repo: &Path, selected: &Path) -> Result<CompileDatabaseSnapshot> {
    let repo = std::fs::canonicalize(repo).context("could not bind compiler database target")?;
    let selected = if selected.is_absolute() {
        selected.to_path_buf()
    } else {
        repo.join(selected)
    };
    let root = if selected.starts_with(&repo) {
        repo.as_path()
    } else {
        selected
            .parent()
            .context("compiler database has no parent directory")?
    };
    let capability = ReadRootCapability::new([root.to_path_buf()])?;
    CompileDatabaseSnapshot::capture(&capability, &selected)
        .context("uaf-hunt: could not freeze the selected compiler database")
}
