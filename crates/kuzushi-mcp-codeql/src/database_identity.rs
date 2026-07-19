use anyhow::{Context, Result};
use kuzushi_mcp_common::{
    AuthorizedChild, AuthorizedDirectory, AuthorizedDirectoryEntry, AuthorizedDirectoryRevisions,
    AuthorizedFile, ReadRootCapability,
};
use std::ffi::OsStr;
use std::io::Write;
use std::path::Path;

pub(crate) const MAX_DATABASE_IDENTITY_ENTRIES: u64 = 500_000;
pub(crate) const MAX_DATABASE_IDENTITY_BYTES: u64 = 64_u64 * 1024 * 1024 * 1024;
const MAX_DATABASE_IDENTITY_DEPTH: usize = 128;

pub(crate) fn database_identity(path: &Path) -> Result<String> {
    let path = std::fs::canonicalize(path)?;
    let capability = ReadRootCapability::new([path.clone()])?;
    let database = capability.authorize_directory(&path)?;
    preflight_database(&database)?;
    hash_database(&database, None)
}

/// Copy a database while deriving the same receipt used by `database_identity`.
/// The disposable destination is removed by its owner if a limit or stability
/// check fails, so a separate preflight pass is unnecessary.
pub(crate) fn copy_database(path: &Path, destination: &Path) -> Result<String> {
    anyhow::ensure!(
        std::fs::read_dir(destination)?.next().is_none(),
        "database snapshot destination is not empty"
    );
    let path = std::fs::canonicalize(path)?;
    let capability = ReadRootCapability::new([path.clone()])?;
    let database = capability.authorize_directory(&path)?;
    hash_database(&database, Some(destination))
}

fn hash_database(database: &AuthorizedDirectory, destination: Option<&Path>) -> Result<String> {
    let mut budget = IdentityBudget::default();
    let mut revisions = AuthorizedDirectoryRevisions::new(database, entry_limit()?)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kuzushi-codeql-database-content-v1\0");
    hash_directory(
        database,
        Path::new(""),
        destination,
        0,
        &mut budget,
        &mut revisions,
        &mut hasher,
    )?;
    revisions.verify_all_unchanged()?;
    Ok(hasher.finalize().to_hex().to_string())
}

fn preflight_database(database: &AuthorizedDirectory) -> Result<()> {
    let mut budget = IdentityBudget::default();
    preflight_directory(database, 0, &mut budget)?;
    database.verify_revision_unchanged()
}

fn preflight_directory(
    directory: &AuthorizedDirectory,
    depth: usize,
    budget: &mut IdentityBudget,
) -> Result<()> {
    ensure_depth(depth)?;
    for entry in bounded_children(directory, budget.remaining_entries())? {
        preflight_entry(directory, &entry, depth, budget)?;
    }
    directory.verify_revision_unchanged()
}

fn preflight_entry(
    directory: &AuthorizedDirectory,
    entry: &AuthorizedDirectoryEntry,
    depth: usize,
    budget: &mut IdentityBudget,
) -> Result<()> {
    budget.reserve_entry()?;
    match directory.open_child(entry)? {
        AuthorizedChild::Directory(child) => preflight_directory(&child, depth + 1, budget),
        AuthorizedChild::File(file) => budget.reserve_bytes(file.byte_len()),
    }
}

fn hash_directory(
    directory: &AuthorizedDirectory,
    relative: &Path,
    destination: Option<&Path>,
    depth: usize,
    budget: &mut IdentityBudget,
    revisions: &mut AuthorizedDirectoryRevisions,
    hasher: &mut blake3::Hasher,
) -> Result<()> {
    ensure_depth(depth)?;
    let entries = bounded_children(directory, budget.remaining_entries())?;
    revisions.retain(directory, &entries)?;
    for entry in entries {
        hash_entry(
            directory,
            relative,
            &entry,
            destination,
            depth,
            budget,
            revisions,
            hasher,
        )?;
    }
    hasher.update(b"e");
    directory.verify_revision_unchanged()
}

#[allow(clippy::too_many_arguments)]
fn hash_entry(
    directory: &AuthorizedDirectory,
    parent: &Path,
    entry: &AuthorizedDirectoryEntry,
    destination: Option<&Path>,
    depth: usize,
    budget: &mut IdentityBudget,
    revisions: &mut AuthorizedDirectoryRevisions,
    hasher: &mut blake3::Hasher,
) -> Result<()> {
    budget.reserve_entry()?;
    let relative = parent.join(entry.name());
    match directory.open_child(entry)? {
        AuthorizedChild::Directory(child) => {
            hash_entry_header(hasher, b'd', entry.name(), 0);
            prepare_output_directory(destination, &relative)?;
            hash_directory(
                &child,
                &relative,
                destination,
                depth + 1,
                budget,
                revisions,
                hasher,
            )
        }
        AuthorizedChild::File(file) => {
            hash_file(file, &relative, entry.name(), destination, budget, hasher)
        }
    }
}

fn prepare_output_directory(destination: Option<&Path>, relative: &Path) -> Result<()> {
    let Some(destination) = destination else {
        return Ok(());
    };
    std::fs::create_dir(destination.join(relative))?;
    Ok(())
}

fn hash_file(
    file: AuthorizedFile,
    relative: &Path,
    name: &OsStr,
    destination: Option<&Path>,
    budget: &mut IdentityBudget,
    hasher: &mut blake3::Hasher,
) -> Result<()> {
    let max_bytes =
        usize::try_from(file.byte_len()).context("CodeQL database file is too large")?;
    let permissions = file.permissions();
    let file = file.into_bounded(max_bytes)?;
    let bytes = file.identity().len;
    budget.reserve_bytes(bytes)?;
    hash_entry_header(hasher, b'f', name, bytes);
    copy_and_hash_file(file, destination, relative, permissions, hasher)
}

fn copy_and_hash_file(
    file: kuzushi_mcp_common::BoundedReadFile,
    destination: Option<&Path>,
    relative: &Path,
    permissions: std::fs::Permissions,
    hasher: &mut blake3::Hasher,
) -> Result<()> {
    let output_path = destination.map(|root| root.join(relative));
    let mut output = output_path
        .as_ref()
        .map(|path| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
        })
        .transpose()?;
    file.for_each_chunk(|chunk| {
        hasher.update(chunk);
        if let Some(output) = output.as_mut() {
            output.write_all(chunk)?;
        }
        Ok(())
    })?;
    if let Some((output, path)) = output.zip(output_path) {
        drop(output);
        std::fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn bounded_children(
    directory: &AuthorizedDirectory,
    remaining_entries: usize,
) -> Result<Vec<AuthorizedDirectoryEntry>> {
    directory
        .entries(remaining_entries)
        .with_context(|| "CodeQL database exceeds the file-count limit or could not be enumerated")
}

fn ensure_depth(depth: usize) -> Result<()> {
    anyhow::ensure!(
        depth <= MAX_DATABASE_IDENTITY_DEPTH,
        "CodeQL database nesting is too deep"
    );
    Ok(())
}

fn entry_limit() -> Result<usize> {
    usize::try_from(MAX_DATABASE_IDENTITY_ENTRIES)
        .context("CodeQL database entry limit exceeds this platform")
}

fn hash_entry_header(hasher: &mut blake3::Hasher, kind: u8, name: &OsStr, size: u64) {
    let name = encoded_name(name);
    hasher.update(&[kind]);
    hasher.update(&(name.len() as u64).to_le_bytes());
    hasher.update(&name);
    hasher.update(&size.to_le_bytes());
}

#[cfg(unix)]
fn encoded_name(name: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    name.as_bytes().to_vec()
}

#[cfg(windows)]
fn encoded_name(name: &OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    name.encode_wide().flat_map(u16::to_le_bytes).collect()
}

#[cfg(not(any(unix, windows)))]
fn encoded_name(name: &OsStr) -> Vec<u8> {
    name.to_string_lossy().as_bytes().to_vec()
}

#[derive(Default)]
struct IdentityBudget {
    entries: u64,
    bytes: u64,
}

impl IdentityBudget {
    fn reserve_entry(&mut self) -> Result<()> {
        self.entries = self.entries.saturating_add(1);
        anyhow::ensure!(
            self.entries <= MAX_DATABASE_IDENTITY_ENTRIES,
            "CodeQL database exceeds the file-count limit"
        );
        Ok(())
    }

    fn remaining_entries(&self) -> usize {
        MAX_DATABASE_IDENTITY_ENTRIES.saturating_sub(self.entries) as usize
    }

    fn reserve_bytes(&mut self, bytes: u64) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .context("CodeQL database byte count overflowed")?;
        anyhow::ensure!(
            self.bytes <= MAX_DATABASE_IDENTITY_BYTES,
            "CodeQL database exceeds the promotion byte limit"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
