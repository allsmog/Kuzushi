use super::file_snapshot::{stream_exact_file, verify_source_unchanged};
use super::limits::{TraversalBudget, MAX_DATABASE_DEPTH};
use super::secure_tree::{SecureDirectory, SecureEntry};
use super::{codeql_database_is_valid, database_identity, DatabaseIdentity};
use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::Path;

pub(super) struct StagedDatabase {
    pub(super) directory: tempfile::TempDir,
    pub(super) identity: DatabaseIdentity,
}

pub(super) fn stage_database_copy(source: &Path, destination: &Path) -> Result<StagedDatabase> {
    let parent = destination
        .parent()
        .context("CodeQL output has no parent")?;
    let staged = tempfile::Builder::new()
        .prefix(".codeql-db-stage-")
        .tempdir_in(parent)
        .context("could not stage the trusted CodeQL database")?;
    copy_database_tree(source, staged.path())?;
    anyhow::ensure!(
        codeql_database_is_valid(staged.path()),
        "staged CodeQL database failed validation"
    );
    let identity = database_identity(staged.path())?;
    Ok(StagedDatabase {
        directory: staged,
        identity,
    })
}

fn copy_database_tree(source: &Path, destination: &Path) -> Result<()> {
    let source = SecureDirectory::open(source)
        .with_context(|| format!("opening CodeQL database {}", source.display()))?;
    let mut budget = TraversalBudget::default();
    copy_directory_contents(&source, destination, 0, &mut budget)
}

fn copy_directory_contents(
    source: &SecureDirectory,
    destination: &Path,
    depth: usize,
    budget: &mut TraversalBudget,
) -> Result<()> {
    anyhow::ensure!(
        depth <= MAX_DATABASE_DEPTH,
        "CodeQL database nesting is too deep"
    );
    let capacity = budget.remaining_entry_capacity();
    for name in source
        .entry_names(capacity)
        .with_context(|| format!("reading {}", source.path().display()))?
    {
        copy_database_entry(source, &name, destination, depth, budget)?;
    }
    Ok(())
}

fn copy_database_entry(
    source: &SecureDirectory,
    name: &OsStr,
    destination: &Path,
    depth: usize,
    budget: &mut TraversalBudget,
) -> Result<()> {
    budget.reserve_entry()?;
    let source_path = source.path().join(name);
    let target = destination.join(name);
    match source.open_entry(name) {
        Ok(SecureEntry::Directory(directory)) => {
            fs::create_dir(&target)?;
            copy_directory_contents(&directory, &target, depth + 1, budget)
        }
        Ok(SecureEntry::File(file, metadata)) => {
            copy_regular_file(file, metadata, &source_path, &target, budget)
        }
        Err(error) => Err(error).with_context(|| format!("opening {}", source_path.display())),
    }
}

fn copy_regular_file(
    mut source: fs::File,
    metadata: fs::Metadata,
    source_path: &Path,
    target: &Path,
    budget: &mut TraversalBudget,
) -> Result<()> {
    budget.reserve_file_bytes(metadata.len())?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)?;
    stream_exact_file(&mut source, metadata.len(), |bytes| output.write_all(bytes))
        .with_context(|| format!("copying {}", source_path.display()))?;
    verify_source_unchanged(&source, &metadata, source_path)?;
    drop(output);
    fs::set_permissions(target, metadata.permissions())?;
    Ok(())
}

#[cfg(test)]
pub(super) fn copy_entry_for_test(
    source: &SecureDirectory,
    name: &OsStr,
    destination: &Path,
) -> Result<()> {
    copy_database_entry(
        source,
        name,
        destination,
        0,
        &mut TraversalBudget::default(),
    )
}
