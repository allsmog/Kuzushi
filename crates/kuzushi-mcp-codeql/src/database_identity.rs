use anyhow::{Context, Result};
use kuzushi_mcp_common::{AuthorizedDirectory, ReadRootCapability};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

pub(crate) const MAX_DATABASE_IDENTITY_ENTRIES: u64 = 500_000;
pub(crate) const MAX_DATABASE_IDENTITY_BYTES: u64 = 64_u64 * 1024 * 1024 * 1024;
const MAX_DATABASE_IDENTITY_DEPTH: usize = 128;

pub(crate) fn database_identity(path: &Path) -> Result<String> {
    let path = std::fs::canonicalize(path)?;
    let capability = ReadRootCapability::new([path.clone()])?;
    let database = capability.authorize_directory(&path)?;
    preflight_database(&capability, &database, &path)?;
    let mut budget = IdentityBudget::default();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kuzushi-codeql-database-content-v1\0");
    hash_directory(&capability, &database, &path, 0, &mut budget, &mut hasher)?;
    database.verify_unchanged()?;
    Ok(hasher.finalize().to_hex().to_string())
}

fn preflight_database(
    capability: &ReadRootCapability,
    database: &AuthorizedDirectory,
    path: &Path,
) -> Result<()> {
    let mut budget = IdentityBudget::default();
    preflight_directory(capability, database, path, 0, &mut budget)?;
    database.verify_unchanged()
}

fn preflight_directory(
    capability: &ReadRootCapability,
    database: &AuthorizedDirectory,
    path: &Path,
    depth: usize,
    budget: &mut IdentityBudget,
) -> Result<()> {
    ensure_depth(depth)?;
    let directory = capability.authorize_directory(path)?;
    for entry in bounded_children(&directory, budget.remaining_entries())? {
        preflight_entry(capability, database, entry.path(), depth, budget)?;
    }
    directory.verify_unchanged()
}

fn preflight_entry(
    capability: &ReadRootCapability,
    database: &AuthorizedDirectory,
    path: PathBuf,
    depth: usize,
    budget: &mut IdentityBudget,
) -> Result<()> {
    budget.reserve_entry()?;
    let metadata = checked_entry_metadata(&path)?;
    if metadata.is_dir() {
        return preflight_directory(capability, database, &path, depth + 1, budget);
    }
    let _ = path.strip_prefix(database.path())?;
    budget.reserve_bytes(metadata.len())
}

fn hash_directory(
    capability: &ReadRootCapability,
    database: &AuthorizedDirectory,
    path: &Path,
    depth: usize,
    budget: &mut IdentityBudget,
    hasher: &mut blake3::Hasher,
) -> Result<()> {
    ensure_depth(depth)?;
    let directory = capability.authorize_directory(path)?;
    for entry in bounded_children(&directory, budget.remaining_entries())? {
        hash_entry(capability, database, entry.path(), depth, budget, hasher)?;
    }
    hasher.update(b"e");
    directory.verify_unchanged()
}

fn hash_entry(
    capability: &ReadRootCapability,
    database: &AuthorizedDirectory,
    path: PathBuf,
    depth: usize,
    budget: &mut IdentityBudget,
    hasher: &mut blake3::Hasher,
) -> Result<()> {
    budget.reserve_entry()?;
    let metadata = checked_entry_metadata(&path)?;
    let name = path
        .file_name()
        .context("CodeQL database entry has no name")?;
    if metadata.is_dir() {
        hash_entry_header(hasher, b'd', name, 0);
        return hash_directory(capability, database, &path, depth + 1, budget, hasher);
    }
    hash_file(database, &path, name, &metadata, budget, hasher)
}

fn hash_file(
    database: &AuthorizedDirectory,
    path: &Path,
    name: &OsStr,
    metadata: &std::fs::Metadata,
    budget: &mut IdentityBudget,
    hasher: &mut blake3::Hasher,
) -> Result<()> {
    budget.reserve_bytes(metadata.len())?;
    hash_entry_header(hasher, b'f', name, metadata.len());
    let relative = path.strip_prefix(database.path())?;
    let max_bytes = usize::try_from(metadata.len()).context("CodeQL database file is too large")?;
    database
        .open_file(relative, max_bytes)?
        .for_each_chunk(|bytes| {
            hasher.update(bytes);
            Ok(())
        })
}

fn bounded_children(
    directory: &AuthorizedDirectory,
    remaining_entries: usize,
) -> Result<Vec<std::fs::DirEntry>> {
    let read_limit = remaining_entries
        .checked_add(1)
        .context("CodeQL database entry read limit overflow")?;
    let mut children = std::fs::read_dir(directory.path())?
        .take(read_limit)
        .collect::<std::io::Result<Vec<_>>>()?;
    anyhow::ensure!(
        children.len() <= remaining_entries,
        "CodeQL database exceeds the file-count limit"
    );
    children.sort_by_key(std::fs::DirEntry::file_name);
    Ok(children)
}

fn checked_entry_metadata(path: &Path) -> Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "CodeQL database contains a symbolic link"
    );
    anyhow::ensure!(
        metadata.is_dir() || metadata.is_file(),
        "CodeQL database contains a non-regular entry"
    );
    Ok(metadata)
}

fn ensure_depth(depth: usize) -> Result<()> {
    anyhow::ensure!(
        depth <= MAX_DATABASE_IDENTITY_DEPTH,
        "CodeQL database nesting is too deep"
    );
    Ok(())
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
mod tests {
    use super::*;

    #[test]
    fn identity_changes_for_same_size_content() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("entry");
        std::fs::write(&file, "one").unwrap();
        let first = database_identity(temp.path()).unwrap();

        std::fs::write(&file, "two").unwrap();
        let second = database_identity(temp.path()).unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn preflight_rejects_total_content_above_the_promotion_bound() {
        let temp = tempfile::tempdir().unwrap();
        for name in ["first", "second"] {
            std::fs::File::create(temp.path().join(name))
                .unwrap()
                .set_len(MAX_DATABASE_IDENTITY_BYTES / 2 + 1)
                .unwrap();
        }

        let error = database_identity(temp.path()).unwrap_err().to_string();

        assert!(error.contains("promotion byte limit"), "{error}");
    }

    #[test]
    fn enumeration_reads_only_remaining_capacity_plus_one() {
        let temp = tempfile::tempdir().unwrap();
        for name in ["one", "two", "three"] {
            std::fs::write(temp.path().join(name), name).unwrap();
        }
        let capability = ReadRootCapability::new([temp.path().to_path_buf()]).unwrap();
        let directory = capability.authorize_directory(temp.path()).unwrap();

        let error = bounded_children(&directory, 2).unwrap_err().to_string();

        assert!(error.contains("file-count limit"), "{error}");
    }
}
