use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

mod file_snapshot;
mod limits;
mod secure_tree;
mod tree_copy;
mod tree_identity;

#[cfg(test)]
mod tests;

use tree_copy::stage_database_copy;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum DestinationState {
    Missing,
    ValidDatabase(DatabaseIdentity),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DatabaseIdentity(String);

impl DatabaseIdentity {
    pub(super) fn from_receipt(value: String) -> Self {
        Self(value)
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(super) fn database_identity(path: &Path) -> Result<DatabaseIdentity> {
    tree_identity::database_identity(path)
}

pub(super) fn inspect_destination(path: &Path) -> Result<DestinationState> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            inspect_existing_database(path)
        }
        Ok(_) => anyhow::bail!(
            "refusing to replace unsafe CodeQL output at {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(DestinationState::Missing),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn inspect_existing_database(path: &Path) -> Result<DestinationState> {
    anyhow::ensure!(
        codeql_database_is_valid(path),
        "refusing to replace non-CodeQL output at {}",
        path.display()
    );
    Ok(DestinationState::ValidDatabase(database_identity(path)?))
}

pub(crate) fn codeql_database_is_valid(path: &Path) -> bool {
    codeql_database_has_shape(path)
        && super::provenance::read_codeql_database_provenance(path).is_ok()
}

pub(super) fn codeql_database_has_shape(path: &Path) -> bool {
    database_root_is_safe(path)
        && codeql_marker_is_valid(path)
        && codeql_database_has_language_dir(path)
}

fn database_root_is_safe(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
}

fn codeql_marker_is_valid(path: &Path) -> bool {
    fs::symlink_metadata(path.join("codeql-database.yml"))
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}

fn codeql_database_has_language_dir(path: &Path) -> bool {
    fs::read_dir(path)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .any(is_codeql_language_directory)
}

fn is_codeql_language_directory(entry: fs::DirEntry) -> bool {
    entry.file_name().to_string_lossy().starts_with("db-")
        && entry
            .file_type()
            .is_ok_and(|kind| kind.is_dir() && !kind.is_symlink())
}

pub(super) fn promote_database(
    workspace: &Path,
    isolated_db: &Path,
    destination: &Path,
    expected_state: DestinationState,
) -> Result<DatabaseIdentity> {
    validate_isolated_database(isolated_db)?;
    let staged = stage_database_copy(isolated_db, destination)?;
    anyhow::ensure!(
        inspect_destination(destination)? == expected_state,
        "CodeQL destination changed during isolated execution; retry"
    );
    install_staged_database(workspace, destination, staged.directory, &expected_state)?;
    Ok(staged.identity)
}

fn validate_isolated_database(isolated_db: &Path) -> Result<()> {
    anyhow::ensure!(
        codeql_database_is_valid(isolated_db),
        "CodeQL reported success without a complete database and trusted provenance in the isolated checkout"
    );
    Ok(())
}

fn install_staged_database(
    workspace: &Path,
    destination: &Path,
    staged: tempfile::TempDir,
    state: &DestinationState,
) -> Result<()> {
    if *state == DestinationState::Missing {
        fs::rename(staged.path(), destination).context("publishing trusted CodeQL database")?;
        return sync_database_parent(destination);
    }
    replace_existing_database(workspace, destination, staged.path(), state)
}

fn replace_existing_database(
    workspace: &Path,
    destination: &Path,
    staged: &Path,
    expected: &DestinationState,
) -> Result<()> {
    let backup = backup_path(workspace, destination)?;
    fs::rename(destination, &backup).context("backing up the previous CodeQL database")?;
    if !backup_matches_expected(&backup, expected) {
        return restore_changed_database(destination, &backup);
    }
    if let Err(error) = fs::rename(staged, destination) {
        return restore_previous_database(destination, &backup, error);
    }
    fs::remove_dir_all(&backup).context("removing the previous CodeQL database backup")?;
    sync_database_parent(destination)
}

fn backup_path(workspace: &Path, destination: &Path) -> Result<std::path::PathBuf> {
    let parent = destination
        .parent()
        .context("CodeQL output has no parent")?;
    let backup = parent.join(format!(".codeql-db-backup-{}", uuid::Uuid::new_v4()));
    validate_backup_path(workspace, &backup)?;
    Ok(backup)
}

fn backup_matches_expected(backup: &Path, expected: &DestinationState) -> bool {
    inspect_destination(backup)
        .map(|actual| &actual == expected)
        .unwrap_or(false)
}

fn restore_changed_database(destination: &Path, backup: &Path) -> Result<()> {
    fs::rename(backup, destination)
        .context("restoring CodeQL database changed during isolated execution")?;
    anyhow::bail!("CodeQL destination changed during isolated execution; retry")
}

fn validate_backup_path(workspace: &Path, backup: &Path) -> Result<()> {
    let relative = backup
        .strip_prefix(workspace)
        .context("CodeQL backup escaped workspace")?;
    crate::workspace::prepare_workspace_output_path(workspace, relative)?;
    Ok(())
}

fn restore_previous_database(
    destination: &Path,
    backup: &Path,
    publish_error: std::io::Error,
) -> Result<()> {
    fs::rename(backup, destination).with_context(|| {
        format!("publishing the new CodeQL database failed ({publish_error}); restoring the previous database also failed")
    })?;
    Err(publish_error).context("publishing trusted CodeQL database")
}

fn sync_database_parent(destination: &Path) -> Result<()> {
    crate::fs_atomic::sync_parent_dir(destination)
        .with_context(|| format!("syncing parent of {}", destination.display()))
}
