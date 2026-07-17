use anyhow::{Context, Result};
use sha2::{Digest as _, Sha256};
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const MAX_WATCHED_FILE_BYTES: u64 = 1024 * 1024;
const MAX_TOTAL_WATCHED_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct PolicySnapshot {
    watched: Vec<WatchedPath>,
    environment: Vec<(OsString, OsString)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WatchedPath {
    path: PathBuf,
    stamp: PathStamp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PathStamp {
    kind: PathKind,
    length: u64,
    modified: Option<SystemTime>,
    readonly: bool,
    content_sha256: Option<[u8; 32]>,
    #[cfg(unix)]
    unix_identity: UnixIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathKind {
    Missing,
    File,
    Directory,
    Symlink,
    Other,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct UnixIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl PolicySnapshot {
    pub(super) fn capture(paths: impl IntoIterator<Item = PathBuf>) -> Result<Self> {
        let mut paths = paths.into_iter().collect::<Vec<_>>();
        paths.sort();
        paths.dedup();
        let watched = capture_watched_paths(paths)?;
        Ok(Self {
            watched,
            environment: git_environment(),
        })
    }

    pub(super) fn capture_current(&self) -> Result<Self> {
        Self::capture(self.watched.iter().map(|watched| watched.path.clone()))
    }

    #[cfg(test)]
    pub(super) fn empty_for_test() -> Self {
        Self {
            watched: Vec::new(),
            environment: Vec::new(),
        }
    }
}

fn capture_watched_paths(paths: Vec<PathBuf>) -> Result<Vec<WatchedPath>> {
    let mut total_bytes = 0_u64;
    let mut watched = Vec::with_capacity(paths.len());
    for path in paths {
        let item = WatchedPath::capture(path)?;
        total_bytes = total_bytes
            .checked_add(item.stamp.hashed_bytes())
            .context("Git policy input byte count overflowed")?;
        anyhow::ensure!(
            total_bytes <= MAX_TOTAL_WATCHED_BYTES,
            "Git policy inputs exceed the {MAX_TOTAL_WATCHED_BYTES}-byte cache verification limit"
        );
        watched.push(item);
    }
    Ok(watched)
}

impl WatchedPath {
    fn capture(path: PathBuf) -> Result<Self> {
        let stamp = PathStamp::capture(&path).map_err(|error| {
            anyhow::anyhow!(
                "Could not inspect Git policy input {}: {error:#}",
                path.display()
            )
        })?;
        Ok(Self { path, stamp })
    }
}

impl PathStamp {
    fn capture(path: &Path) -> Result<Self> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::missing())
            }
            Err(error) => return Err(error.into()),
        };
        let mut stamp = Self::from_metadata(&metadata);
        if stamp.kind == PathKind::File {
            stamp.content_sha256 = Some(hash_regular_file(path, &stamp)?);
            let after = std::fs::symlink_metadata(path)?;
            anyhow::ensure!(
                stamp.same_file_metadata(&after),
                "Git policy input changed while it was hashed: {}",
                path.display()
            );
        }
        Ok(stamp)
    }

    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            kind: path_kind(metadata),
            length: metadata.len(),
            modified: metadata.modified().ok(),
            readonly: metadata.permissions().readonly(),
            content_sha256: None,
            #[cfg(unix)]
            unix_identity: unix_identity(metadata),
        }
    }

    fn missing() -> Self {
        Self {
            kind: PathKind::Missing,
            length: 0,
            modified: None,
            readonly: false,
            content_sha256: None,
            #[cfg(unix)]
            unix_identity: UnixIdentity::default(),
        }
    }

    fn hashed_bytes(&self) -> u64 {
        self.content_sha256.map_or(0, |_| self.length)
    }

    fn same_file_metadata(&self, metadata: &std::fs::Metadata) -> bool {
        let current = Self::from_metadata(metadata);
        self.kind == current.kind
            && self.length == current.length
            && self.modified == current.modified
            && self.readonly == current.readonly
            && same_unix_identity(self, &current)
    }
}

fn hash_regular_file(path: &Path, expected: &PathStamp) -> Result<[u8; 32]> {
    anyhow::ensure!(
        expected.length <= MAX_WATCHED_FILE_BYTES,
        "Git policy input {} is {} bytes; cache verification limit is {MAX_WATCHED_FILE_BYTES}",
        path.display(),
        expected.length
    );
    let mut file = open_regular_nofollow(path)?;
    anyhow::ensure!(
        expected.same_file_metadata(&file.metadata()?),
        "Git policy input changed before it was hashed: {}",
        path.display()
    );
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .context("Git policy input byte count overflowed")?;
        anyhow::ensure!(
            bytes <= MAX_WATCHED_FILE_BYTES,
            "Git policy input {} exceeded the {MAX_WATCHED_FILE_BYTES}-byte cache verification limit",
            path.display()
        );
        hasher.update(&buffer[..count]);
    }
    anyhow::ensure!(
        bytes == expected.length,
        "Git policy input changed while it was hashed: {}",
        path.display()
    );
    Ok(hasher.finalize().into())
}

#[cfg(unix)]
fn open_regular_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_regular_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

fn path_kind(metadata: &std::fs::Metadata) -> PathKind {
    let kind = metadata.file_type();
    if kind.is_symlink() {
        PathKind::Symlink
    } else if kind.is_file() {
        PathKind::File
    } else if kind.is_dir() {
        PathKind::Directory
    } else {
        PathKind::Other
    }
}

#[cfg(unix)]
fn unix_identity(metadata: &std::fs::Metadata) -> UnixIdentity {
    use std::os::unix::fs::MetadataExt;
    UnixIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[cfg(unix)]
fn same_unix_identity(left: &PathStamp, right: &PathStamp) -> bool {
    left.unix_identity == right.unix_identity
}

#[cfg(not(unix))]
fn same_unix_identity(_left: &PathStamp, _right: &PathStamp) -> bool {
    true
}

fn git_environment() -> Vec<(OsString, OsString)> {
    let mut environment = std::env::vars_os()
        .filter(|(key, _)| is_git_environment_key(key))
        .collect::<Vec<_>>();
    environment.sort_by(|left, right| left.0.cmp(&right.0));
    environment
}

fn is_git_environment_key(key: &std::ffi::OsStr) -> bool {
    let key = key.to_string_lossy();
    key.starts_with("GIT_") || matches!(key.as_ref(), "HOME" | "XDG_CONFIG_HOME")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_length_file_edit_changes_snapshot_content_identity() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("policy");
        std::fs::write(&path, "alpha").unwrap();
        let before = PolicySnapshot::capture([path.clone()]).unwrap();

        std::fs::write(&path, "bravo").unwrap();
        let after = PolicySnapshot::capture([path]).unwrap();

        assert_ne!(before, after);
    }

    #[test]
    fn oversized_policy_input_fails_instead_of_using_metadata_only() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("oversized-policy");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_WATCHED_FILE_BYTES + 1).unwrap();

        let error = PolicySnapshot::capture([path]).unwrap_err().to_string();

        assert!(error.contains("cache verification limit"), "{error}");
    }
}
