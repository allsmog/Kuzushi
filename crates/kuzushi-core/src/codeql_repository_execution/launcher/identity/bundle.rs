use anyhow::{Context, Result};
use kuzushi_mcp_common::{AuthorizedDirectory, ReadRootCapability};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::Path;

pub(in crate::codeql_repository_execution::launcher) const MAX_EXTERNAL_BUNDLE_ENTRIES: u64 =
    500_000;
pub(in crate::codeql_repository_execution::launcher) const MAX_EXTERNAL_BUNDLE_BYTES: u64 =
    16 * 1024 * 1024 * 1024;
pub(in crate::codeql_repository_execution::launcher) const MAX_EXTERNAL_BUNDLE_DEPTH: usize = 128;

#[derive(Default)]
struct BundleBudget {
    entries: u64,
    bytes: u64,
}

pub(in crate::codeql_repository_execution::launcher) fn external_bundle_identity(
    root: &Path,
) -> Result<String> {
    let root = fs::canonicalize(root)
        .with_context(|| format!("could not resolve CodeQL bundle {}", root.display()))?;
    let capability = ReadRootCapability::new([root.clone()])?;
    let directory = capability.authorize_directory(&root)?;
    let mut budget = BundleBudget::default();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kuzushi-codeql-external-bundle-v1\0");
    hash_directory(
        &capability,
        &directory,
        Path::new(""),
        0,
        &mut budget,
        &mut hasher,
    )?;
    directory.verify_unchanged()?;
    Ok(hasher.finalize().to_hex().to_string())
}

pub(in crate::codeql_repository_execution::launcher) fn verify_external_bundle_identity(
    root: &Path,
    expected: &str,
) -> Result<()> {
    anyhow::ensure!(
        external_bundle_identity(root)? == expected,
        "CodeQL external bundle changed after preparation; prepare and authorize the operation again"
    );
    Ok(())
}

fn hash_directory(
    capability: &ReadRootCapability,
    root: &AuthorizedDirectory,
    relative: &Path,
    depth: usize,
    budget: &mut BundleBudget,
    hasher: &mut blake3::Hasher,
) -> Result<()> {
    anyhow::ensure!(
        depth <= MAX_EXTERNAL_BUNDLE_DEPTH,
        "CodeQL external bundle nesting exceeds the {MAX_EXTERNAL_BUNDLE_DEPTH}-level limit"
    );
    let directory = capability.authorize_directory(&root.path().join(relative))?;
    let before = DirectoryRevision::read(directory.path())?;
    hasher.update(b"d");
    for name in bounded_entry_names(directory.path(), budget)? {
        hash_entry(capability, root, relative, &name, depth, budget, hasher)?;
    }
    hasher.update(b"e");
    verify_directory_stable(&directory, &before)
}

fn hash_entry(
    capability: &ReadRootCapability,
    root: &AuthorizedDirectory,
    parent: &Path,
    name: &OsStr,
    depth: usize,
    budget: &mut BundleBudget,
    hasher: &mut blake3::Hasher,
) -> Result<()> {
    budget.reserve_entry()?;
    let relative = parent.join(name);
    let path = root.path().join(&relative);
    let metadata = fs::symlink_metadata(&path)?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "CodeQL external bundle contains a symbolic link: {}",
        path.display()
    );
    if metadata.is_dir() {
        frame_entry(hasher, b'd', name);
        return hash_directory(capability, root, &relative, depth + 1, budget, hasher);
    }
    anyhow::ensure!(
        metadata.is_file(),
        "CodeQL external bundle contains a non-regular entry: {}",
        path.display()
    );
    hash_file(root, &relative, name, budget, hasher)
}

fn hash_file(
    root: &AuthorizedDirectory,
    relative: &Path,
    name: &OsStr,
    budget: &mut BundleBudget,
    hasher: &mut blake3::Hasher,
) -> Result<()> {
    let remaining = MAX_EXTERNAL_BUNDLE_BYTES.saturating_sub(budget.bytes);
    let max_bytes =
        usize::try_from(remaining).context("CodeQL bundle limit exceeds this platform")?;
    let file = root.open_file(relative, max_bytes)?;
    let bytes = file.identity().len;
    budget.reserve_bytes(bytes)?;
    let digest = file.copy_to_with_sha256_hex(&mut std::io::sink())?;
    frame_entry(hasher, b'f', name);
    hasher.update(&bytes.to_le_bytes());
    hasher.update(&(digest.len() as u64).to_le_bytes());
    hasher.update(digest.as_bytes());
    Ok(())
}

fn bounded_entry_names(path: &Path, budget: &BundleBudget) -> Result<Vec<OsString>> {
    let remaining = MAX_EXTERNAL_BUNDLE_ENTRIES.saturating_sub(budget.entries) as usize;
    let mut names = fs::read_dir(path)?
        .take(remaining.saturating_add(1))
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    anyhow::ensure!(
        names.len() <= remaining,
        "CodeQL external bundle exceeds the {MAX_EXTERNAL_BUNDLE_ENTRIES}-entry limit"
    );
    names.sort();
    Ok(names)
}

fn frame_entry(hasher: &mut blake3::Hasher, kind: u8, name: &OsStr) {
    let name = encoded_name(name);
    hasher.update(&[kind]);
    hasher.update(&(name.len() as u64).to_le_bytes());
    hasher.update(&name);
}

impl BundleBudget {
    fn reserve_entry(&mut self) -> Result<()> {
        self.entries = self
            .entries
            .checked_add(1)
            .context("CodeQL bundle entry overflow")?;
        anyhow::ensure!(
            self.entries <= MAX_EXTERNAL_BUNDLE_ENTRIES,
            "CodeQL external bundle exceeds the {MAX_EXTERNAL_BUNDLE_ENTRIES}-entry limit"
        );
        Ok(())
    }

    fn reserve_bytes(&mut self, bytes: u64) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .context("CodeQL bundle byte overflow")?;
        anyhow::ensure!(
            self.bytes <= MAX_EXTERNAL_BUNDLE_BYTES,
            "CodeQL external bundle exceeds the {MAX_EXTERNAL_BUNDLE_BYTES}-byte limit"
        );
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
struct DirectoryRevision {
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    change_seconds: i64,
    #[cfg(unix)]
    change_nanos: i64,
    #[cfg(windows)]
    created: u64,
    #[cfg(windows)]
    written: u64,
    #[cfg(windows)]
    attributes: u32,
}

impl DirectoryRevision {
    fn read(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "CodeQL external bundle directory changed type: {}",
            path.display()
        );
        Ok(Self::from_metadata(&metadata))
    }

    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: unix_metadata::device(metadata),
            #[cfg(unix)]
            inode: unix_metadata::inode(metadata),
            #[cfg(unix)]
            change_seconds: unix_metadata::change_seconds(metadata),
            #[cfg(unix)]
            change_nanos: unix_metadata::change_nanos(metadata),
            #[cfg(windows)]
            created: windows_metadata::created(metadata),
            #[cfg(windows)]
            written: windows_metadata::written(metadata),
            #[cfg(windows)]
            attributes: windows_metadata::attributes(metadata),
        }
    }
}

fn verify_directory_stable(
    directory: &AuthorizedDirectory,
    before: &DirectoryRevision,
) -> Result<()> {
    let after = DirectoryRevision::read(directory.path())?;
    anyhow::ensure!(
        after == *before,
        "CodeQL external bundle changed while its identity was computed: {}",
        directory.path().display()
    );
    directory.verify_unchanged()
}

#[cfg(unix)]
mod unix_metadata {
    use std::fs::Metadata;
    use std::os::unix::fs::MetadataExt;

    pub(super) fn device(metadata: &Metadata) -> u64 {
        metadata.dev()
    }

    pub(super) fn inode(metadata: &Metadata) -> u64 {
        metadata.ino()
    }

    pub(super) fn change_seconds(metadata: &Metadata) -> i64 {
        metadata.ctime()
    }

    pub(super) fn change_nanos(metadata: &Metadata) -> i64 {
        metadata.ctime_nsec()
    }
}

#[cfg(windows)]
mod windows_metadata {
    use std::fs::Metadata;
    use std::os::windows::fs::MetadataExt;

    pub(super) fn created(metadata: &Metadata) -> u64 {
        metadata.creation_time()
    }

    pub(super) fn written(metadata: &Metadata) -> u64 {
        metadata.last_write_time()
    }

    pub(super) fn attributes(metadata: &Metadata) -> u32 {
        metadata.file_attributes()
    }
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
    name.to_string_lossy().into_owned().into_bytes()
}
