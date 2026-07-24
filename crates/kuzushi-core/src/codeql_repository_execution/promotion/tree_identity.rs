use super::file_snapshot::{stream_exact_file, verify_source_unchanged};
use super::limits::{TraversalBudget, MAX_DATABASE_DEPTH};
use super::secure_tree::{SecureDirectory, SecureEntry};
use super::DatabaseIdentity;
use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

pub(super) fn database_identity(path: &Path) -> Result<DatabaseIdentity> {
    let root = SecureDirectory::open(path)
        .with_context(|| format!("opening CodeQL database {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kuzushi-codeql-database-content-v1\0");
    let mut budget = TraversalBudget::default();
    hash_directory_contents(&root, 0, &mut budget, &mut hasher)?;
    Ok(DatabaseIdentity(hasher.finalize().to_hex().to_string()))
}

fn hash_directory_contents(
    directory: &SecureDirectory,
    depth: usize,
    budget: &mut TraversalBudget,
    hasher: &mut blake3::Hasher,
) -> Result<()> {
    anyhow::ensure!(
        depth <= MAX_DATABASE_DEPTH,
        "CodeQL database nesting is too deep"
    );
    let capacity = budget.remaining_entry_capacity();
    for name in directory.entry_names(capacity)? {
        hash_database_entry(directory, &name, depth, budget, hasher)?;
    }
    hasher.update(b"e");
    Ok(())
}

fn hash_database_entry(
    directory: &SecureDirectory,
    name: &OsStr,
    depth: usize,
    budget: &mut TraversalBudget,
    hasher: &mut blake3::Hasher,
) -> Result<()> {
    budget.reserve_entry()?;
    match directory.open_entry(name)? {
        SecureEntry::Directory(child) => {
            hash_entry_header(hasher, b'd', name, 0);
            hash_directory_contents(&child, depth + 1, budget, hasher)
        }
        SecureEntry::File(mut file, metadata) => {
            hash_regular_file(&mut file, &metadata, name, budget, hasher)
        }
    }
}

fn hash_regular_file(
    file: &mut fs::File,
    metadata: &fs::Metadata,
    name: &OsStr,
    budget: &mut TraversalBudget,
    hasher: &mut blake3::Hasher,
) -> Result<()> {
    budget.reserve_file_bytes(metadata.len())?;
    hash_entry_header(hasher, b'f', name, metadata.len());
    stream_exact_file(file, metadata.len(), |bytes| {
        hasher.update(bytes);
        Ok(())
    })?;
    verify_source_unchanged(file, metadata, Path::new(name))
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
    name.encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

#[cfg(not(any(unix, windows)))]
fn encoded_name(name: &OsStr) -> Vec<u8> {
    name.to_string_lossy().into_owned().into_bytes()
}
