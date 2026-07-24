use super::directory::{verify_revision, AuthorizedDirectory, AuthorizedDirectoryEntry};
use super::directory_entries;
use super::file::ReadFileIdentity;
use super::open::{open_file_beneath, ReadRoot};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// The receipt cap bounds final reopens to roughly 4.2 million component
/// opens at the maximum supported CodeQL tree depth of 128.
const MAX_DIRECTORY_REVISION_RECEIPTS: usize = 32_768;
/// The aggregate path cap is generous for normal CodeQL layouts while
/// bounding retained receipt memory independently of entry and byte limits.
const MAX_DIRECTORY_REVISION_PATH_BYTES: usize = 16 * 1024 * 1024;

/// Bounded best-effort race detection for a retained tree walk.
///
/// Receipts share one retained read-root handle and supplement handle-relative
/// traversal. Snapshot digest equality remains the primary consistency proof;
/// these receipts do not claim to make a mutable filesystem tree atomic.
#[derive(Debug)]
pub struct AuthorizedDirectoryRevisions {
    root: ReadRoot,
    revisions: Vec<AuthorizedDirectoryRevision>,
    max_revisions: usize,
    max_path_bytes: usize,
    path_bytes: usize,
}

#[derive(Debug)]
struct AuthorizedDirectoryRevision {
    relative: PathBuf,
    identity: ReadFileIdentity,
    entry_count: usize,
    entry_fingerprint: [u8; 32],
}

impl AuthorizedDirectoryRevisions {
    pub fn new(root: &AuthorizedDirectory, max_entries: usize) -> Result<Self> {
        let requested = max_entries
            .checked_add(1)
            .context("MCP directory revision receipt limit overflow")?;
        Ok(Self::with_limits(
            root,
            requested.min(MAX_DIRECTORY_REVISION_RECEIPTS),
            MAX_DIRECTORY_REVISION_PATH_BYTES,
        ))
    }

    fn with_limits(
        root: &AuthorizedDirectory,
        max_revisions: usize,
        max_path_bytes: usize,
    ) -> Self {
        Self {
            root: root.root.clone(),
            revisions: Vec::new(),
            max_revisions,
            max_path_bytes,
            path_bytes: 0,
        }
    }

    pub fn retain(
        &mut self,
        directory: &AuthorizedDirectory,
        entries: &[AuthorizedDirectoryEntry],
    ) -> Result<()> {
        let next_path_bytes = self.ensure_receipt_capacity(directory)?;
        anyhow::ensure!(
            entries
                .iter()
                .all(|entry| entry.parent_identity == directory.identity),
            "MCP directory entries belong to a different retained parent"
        );
        directory.verify_revision_unchanged()?;
        self.revisions.push(AuthorizedDirectoryRevision {
            relative: directory.relative.clone(),
            identity: directory.identity.clone(),
            entry_count: entries.len(),
            entry_fingerprint: directory_entries::fingerprint(
                entries.iter().map(|entry| &entry.record),
            ),
        });
        self.path_bytes = next_path_bytes;
        Ok(())
    }

    pub fn verify_all_unchanged(&self) -> Result<()> {
        for revision in self.revisions.iter().rev() {
            self.verify_revision_unchanged(revision)?;
        }
        Ok(())
    }

    fn ensure_receipt_capacity(&self, directory: &AuthorizedDirectory) -> Result<usize> {
        anyhow::ensure!(
            directory.root.path == self.root.path,
            "MCP directory revision belongs to a different retained read root"
        );
        anyhow::ensure!(
            self.revisions.len() < self.max_revisions,
            "MCP tree exceeds the {}-directory revision receipt limit",
            self.max_revisions
        );
        let next_path_bytes = self
            .path_bytes
            .checked_add(encoded_path_len(&directory.relative)?)
            .context("MCP directory revision path-byte accounting overflow")?;
        anyhow::ensure!(
            next_path_bytes <= self.max_path_bytes,
            "MCP tree exceeds the {}-byte directory revision path limit",
            self.max_path_bytes
        );
        Ok(next_path_bytes)
    }

    fn verify_revision_unchanged(&self, revision: &AuthorizedDirectoryRevision) -> Result<()> {
        let path = self.root.path.join(&revision.relative);
        let directory = open_file_beneath(&self.root, &path)?;
        verify_revision(&directory, &revision.identity, &path)?;
        #[cfg(windows)]
        self.root.ensure_open_by_file_id_supported()?;
        let records =
            directory_entries::entries(&directory, revision.entry_count).with_context(|| {
                format!(
                    "MCP directory entries changed or could not be verified after traversal: {}",
                    path.display()
                )
            })?;
        verify_revision(&directory, &revision.identity, &path)?;
        anyhow::ensure!(
            directory_entries::fingerprint(records.iter()) == revision.entry_fingerprint,
            "MCP directory entries changed after traversal: {}",
            path.display()
        );
        Ok(())
    }
}

#[cfg(unix)]
fn encoded_path_len(path: &Path) -> Result<usize> {
    use std::os::unix::ffi::OsStrExt;
    Ok(path.as_os_str().as_bytes().len())
}

#[cfg(windows)]
fn encoded_path_len(path: &Path) -> Result<usize> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .count()
        .checked_mul(2)
        .context("MCP directory revision path length overflow")
}

#[cfg(not(any(unix, windows)))]
fn encoded_path_len(path: &Path) -> Result<usize> {
    Ok(path.to_string_lossy().len())
}

#[cfg(test)]
mod tests;
