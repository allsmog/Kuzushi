use super::file::{bounded_regular_file, BoundedReadFile, ReadFileIdentity};
use super::open::{identity_for, open_file_beneath, open_visible_directory, ReadRoot};
use super::validate_relative_child;
use anyhow::Result;
use std::fs::File;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct AuthorizedDirectory {
    pub(super) path: PathBuf,
    pub(super) relative: PathBuf,
    pub(super) root: ReadRoot,
    pub(super) file: File,
    pub(super) identity: ReadFileIdentity,
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

    #[cfg(target_os = "linux")]
    pub(crate) fn retained_handle(&self) -> Result<File> {
        self.file.try_clone().map_err(Into::into)
    }
}

fn verify_identity(file: &File, expected: &ReadFileIdentity, path: &Path) -> Result<()> {
    let metadata = file.metadata()?;
    let current = identity_for(file, &metadata)?;
    anyhow::ensure!(
        current.same_file_object(expected),
        "MCP directory changed after authorization: {}",
        path.display()
    );
    Ok(())
}
