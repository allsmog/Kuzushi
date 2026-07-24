use super::file::{bounded_regular_file, BoundedReadFile, ReadFileIdentity};
use super::open::{identity_for, open_file_beneath, open_visible_directory, ReadRoot};
use super::validate_relative_child;
use anyhow::Result;
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata, Permissions};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct AuthorizedDirectory {
    pub(super) path: PathBuf,
    pub(super) relative: PathBuf,
    pub(super) root: ReadRoot,
    pub(super) file: File,
    pub(super) identity: ReadFileIdentity,
}

#[derive(Debug, Clone)]
pub struct AuthorizedDirectoryEntry {
    pub(super) record: super::directory_entries::EntryRecord,
    pub(super) parent_identity: ReadFileIdentity,
}

impl AuthorizedDirectoryEntry {
    pub fn name(&self) -> &OsStr {
        &self.record.name
    }
}

#[derive(Debug)]
pub enum AuthorizedChild {
    Directory(AuthorizedDirectory),
    File(AuthorizedFile),
}

#[derive(Debug)]
pub struct AuthorizedFile {
    path: PathBuf,
    file: File,
    metadata: Metadata,
}

impl AuthorizedFile {
    pub fn byte_len(&self) -> u64 {
        self.metadata.len()
    }

    pub fn permissions(&self) -> Permissions {
        self.metadata.permissions()
    }

    pub fn into_bounded(self, max_bytes: usize) -> Result<BoundedReadFile> {
        bounded_regular_file(self.path, self.file, max_bytes)
    }
}

impl AuthorizedDirectory {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn verify_unchanged(&self) -> Result<()> {
        verify_identity(&self.file, &self.identity, &self.path)?;
        let visible = open_visible_directory(&self.path)?;
        verify_identity(&visible, &self.identity, &self.path)
    }

    pub fn try_clone(&self) -> Result<Self> {
        self.verify_unchanged()?;
        Ok(Self {
            path: self.path.clone(),
            relative: self.relative.clone(),
            root: self.root.clone(),
            file: self.file.try_clone()?,
            identity: self.identity.clone(),
        })
    }

    pub fn open_file(&self, relative: &Path, max_bytes: usize) -> Result<BoundedReadFile> {
        validate_relative_child(relative)?;
        self.verify_unchanged()?;
        let root_relative = self.relative.join(relative);
        let path = self.root.path.join(&root_relative);
        let file = open_file_beneath(&self.root, &path)?;
        bounded_regular_file(path, file, max_bytes)
    }

    /// Enumerate this retained directory and bind every name to the observed
    /// child object. Fails once more than `max_entries` entries are observed.
    pub fn entries(&self, max_entries: usize) -> Result<Vec<AuthorizedDirectoryEntry>> {
        #[cfg(windows)]
        self.root.ensure_open_by_file_id_supported()?;
        let before = retained_identity(&self.file, &self.identity, &self.path)?;
        let records = super::directory_entries::entries(&self.file, max_entries)?;
        let after = retained_identity(&self.file, &self.identity, &self.path)?;
        anyhow::ensure!(
            after == before,
            "MCP directory changed while its entries were enumerated: {}",
            self.path.display()
        );
        Ok(records
            .into_iter()
            .map(|record| AuthorizedDirectoryEntry {
                record,
                parent_identity: self.identity.clone(),
            })
            .collect())
    }

    pub fn entry_names(&self, max_entries: usize) -> Result<Vec<OsString>> {
        self.entries(max_entries)
            .map(|entries| entries.into_iter().map(|entry| entry.record.name).collect())
    }

    pub fn open_child(&self, entry: &AuthorizedDirectoryEntry) -> Result<AuthorizedChild> {
        anyhow::ensure!(
            entry.parent_identity == self.identity,
            "MCP directory entry belongs to a different retained parent"
        );
        verify_identity(&self.file, &self.identity, &self.path)?;
        let path = self.path.join(entry.name());
        let file = super::directory_entries::open_child(&self.file, &entry.record)?;
        super::directory_entries::verify_opened_entry(&entry.record, &file, &path)?;
        self.authorize_opened_child(entry.name(), path, file)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn retained_handle(&self) -> Result<File> {
        self.file.try_clone().map_err(Into::into)
    }
}

impl AuthorizedDirectory {
    fn authorize_opened_child(
        &self,
        name: &OsStr,
        path: PathBuf,
        file: File,
    ) -> Result<AuthorizedChild> {
        let metadata = file.metadata()?;
        if metadata.is_dir() {
            return Ok(AuthorizedChild::Directory(AuthorizedDirectory {
                relative: self.relative.join(name),
                root: self.root.clone(),
                identity: identity_for(&file, &metadata)?,
                path,
                file,
            }));
        }
        anyhow::ensure!(metadata.is_file(), "MCP directory entry is not regular");
        Ok(AuthorizedChild::File(AuthorizedFile {
            path,
            file,
            metadata,
        }))
    }

    pub fn verify_revision_unchanged(&self) -> Result<()> {
        verify_revision(&self.file, &self.identity, &self.path)?;
        let visible = open_visible_directory(&self.path)?;
        verify_revision(&visible, &self.identity, &self.path)
    }
}

fn verify_identity(file: &File, expected: &ReadFileIdentity, path: &Path) -> Result<()> {
    retained_identity(file, expected, path).map(|_| ())
}

fn retained_identity(
    file: &File,
    expected: &ReadFileIdentity,
    path: &Path,
) -> Result<ReadFileIdentity> {
    let metadata = file.metadata()?;
    let current = identity_for(file, &metadata)?;
    anyhow::ensure!(
        current.same_file_object(expected),
        "MCP directory changed after authorization: {}",
        path.display()
    );
    Ok(current)
}

pub(super) fn verify_revision(file: &File, expected: &ReadFileIdentity, path: &Path) -> Result<()> {
    let metadata = file.metadata()?;
    let current = identity_for(file, &metadata)?;
    anyhow::ensure!(
        current == *expected,
        "MCP directory revision changed after authorization: {}",
        path.display()
    );
    Ok(())
}
