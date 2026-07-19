use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

const MAX_DATABASE_ENTRIES: u64 = 500_000;
const MAX_DATABASE_BYTES: u64 = 64_u64 * 1024 * 1024 * 1024;
const MAX_DATABASE_DEPTH: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DestinationState {
    Missing,
    ValidDatabase,
}

pub(super) fn inspect_destination(path: &Path) -> Result<DestinationState> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            anyhow::ensure!(
                codeql_database_is_valid(path),
                "refusing to replace non-CodeQL output at {}",
                path.display()
            );
            Ok(DestinationState::ValidDatabase)
        }
        Ok(_) => anyhow::bail!(
            "refusing to replace unsafe CodeQL output at {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(DestinationState::Missing),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

pub(crate) fn codeql_database_is_valid(path: &Path) -> bool {
    let root_is_directory = fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink());
    root_is_directory && codeql_marker_is_valid(path) && codeql_database_has_language_dir(path)
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
        .any(|entry| {
            entry.file_name().to_string_lossy().starts_with("db-")
                && entry
                    .file_type()
                    .is_ok_and(|kind| kind.is_dir() && !kind.is_symlink())
        })
}

pub(super) fn promote_database(
    workspace: &Path,
    isolated_db: &Path,
    destination: &Path,
    expected_state: DestinationState,
) -> Result<()> {
    validate_isolated_database(isolated_db)?;
    let staged = stage_database_copy(isolated_db, destination)?;
    anyhow::ensure!(
        inspect_destination(destination)? == expected_state,
        "CodeQL destination changed during isolated execution; retry"
    );
    install_staged_database(workspace, destination, staged, expected_state)
}

fn validate_isolated_database(isolated_db: &Path) -> Result<()> {
    anyhow::ensure!(
        codeql_database_is_valid(isolated_db),
        "CodeQL reported success without a valid database in the isolated checkout"
    );
    Ok(())
}

fn stage_database_copy(source: &Path, destination: &Path) -> Result<tempfile::TempDir> {
    let parent = destination
        .parent()
        .context("CodeQL output has no parent")?;
    let staged = tempfile::Builder::new()
        .prefix(".codeql-db-stage-")
        .tempdir_in(parent)
        .context("could not stage the validated CodeQL database")?;
    copy_database_tree(source, staged.path())?;
    anyhow::ensure!(
        codeql_database_is_valid(staged.path()),
        "staged CodeQL database failed validation"
    );
    Ok(staged)
}

#[derive(Default)]
struct CopyBudget {
    entries: u64,
    bytes: u64,
}

fn copy_database_tree(source: &Path, destination: &Path) -> Result<()> {
    let mut budget = CopyBudget::default();
    copy_directory_contents(source, destination, 0, &mut budget)
}

fn copy_directory_contents(
    source: &Path,
    destination: &Path,
    depth: usize,
    budget: &mut CopyBudget,
) -> Result<()> {
    anyhow::ensure!(
        depth <= MAX_DATABASE_DEPTH,
        "CodeQL database nesting is too deep"
    );
    for entry in fs::read_dir(source).with_context(|| format!("reading {}", source.display()))? {
        copy_database_entry(entry?, destination, depth, budget)?;
    }
    Ok(())
}

fn copy_database_entry(
    entry: fs::DirEntry,
    destination: &Path,
    depth: usize,
    budget: &mut CopyBudget,
) -> Result<()> {
    reserve_entry(budget)?;
    let kind = entry.file_type()?;
    let target = destination.join(entry.file_name());
    if kind.is_dir() && !kind.is_symlink() {
        fs::create_dir(&target)?;
        return copy_directory_contents(&entry.path(), &target, depth + 1, budget);
    }
    copy_regular_file(entry, &target, budget)
}

fn copy_regular_file(entry: fs::DirEntry, target: &Path, budget: &mut CopyBudget) -> Result<()> {
    let kind = entry.file_type()?;
    anyhow::ensure!(
        kind.is_file() && !kind.is_symlink(),
        "CodeQL database contains a non-regular entry"
    );
    reserve_file_bytes(budget, entry.metadata()?.len())?;
    fs::copy(entry.path(), target)
        .with_context(|| format!("copying {}", entry.path().display()))?;
    Ok(())
}

fn reserve_entry(budget: &mut CopyBudget) -> Result<()> {
    budget.entries = budget.entries.saturating_add(1);
    anyhow::ensure!(
        budget.entries <= MAX_DATABASE_ENTRIES,
        "CodeQL database exceeds the file-count limit"
    );
    Ok(())
}

fn reserve_file_bytes(budget: &mut CopyBudget, bytes: u64) -> Result<()> {
    budget.bytes = budget
        .bytes
        .checked_add(bytes)
        .context("CodeQL database byte count overflowed")?;
    anyhow::ensure!(
        budget.bytes <= MAX_DATABASE_BYTES,
        "CodeQL database exceeds the promotion byte limit"
    );
    Ok(())
}

fn install_staged_database(
    workspace: &Path,
    destination: &Path,
    staged: tempfile::TempDir,
    state: DestinationState,
) -> Result<()> {
    if state == DestinationState::Missing {
        fs::rename(staged.path(), destination).context("publishing validated CodeQL database")?;
        return sync_database_parent(destination);
    }
    replace_existing_database(workspace, destination, staged.path())
}

fn replace_existing_database(workspace: &Path, destination: &Path, staged: &Path) -> Result<()> {
    let parent = destination
        .parent()
        .context("CodeQL output has no parent")?;
    let backup = parent.join(format!(".codeql-db-backup-{}", uuid::Uuid::new_v4()));
    validate_backup_path(workspace, &backup)?;
    fs::rename(destination, &backup).context("backing up the previous CodeQL database")?;
    if let Err(error) = fs::rename(staged, destination) {
        return restore_previous_database(destination, &backup, error);
    }
    fs::remove_dir_all(&backup).context("removing the previous CodeQL database backup")?;
    sync_database_parent(destination)
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
    Err(publish_error).context("publishing validated CodeQL database")
}

fn sync_database_parent(destination: &Path) -> Result<()> {
    crate::fs_atomic::sync_parent_dir(destination)
        .with_context(|| format!("syncing parent of {}", destination.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promotion_rejects_symlinks_inside_a_reported_database() {
        let workspace = tempfile::tempdir().unwrap();
        let isolated = tempfile::tempdir().unwrap();
        let destination = workspace.path().join(".kuzushi/codeql-db");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        make_valid_database(isolated.path());
        #[cfg(unix)]
        std::os::unix::fs::symlink("codeql-database.yml", isolated.path().join("alias")).unwrap();

        #[cfg(unix)]
        assert!(promote_database(
            workspace.path(),
            isolated.path(),
            &destination,
            DestinationState::Missing,
        )
        .is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn failed_preflight_preserves_non_database_output() {
        let workspace = tempfile::tempdir().unwrap();
        let destination = workspace.path().join(".kuzushi/codeql-db");
        fs::create_dir_all(&destination).unwrap();
        fs::write(destination.join("important.txt"), "keep").unwrap();

        assert!(inspect_destination(&destination).is_err());
        assert_eq!(
            fs::read_to_string(destination.join("important.txt")).unwrap(),
            "keep"
        );
    }

    fn make_valid_database(path: &Path) {
        fs::write(path.join("codeql-database.yml"), "primaryLanguage: cpp\n").unwrap();
        fs::create_dir(path.join("db-cpp")).unwrap();
    }
}
