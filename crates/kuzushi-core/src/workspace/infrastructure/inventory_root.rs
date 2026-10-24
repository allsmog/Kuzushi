//! Repository inventory IO remains attached to its authorized root directory.
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum InventoryEntryKind {
    Directory,
    File,
    Other,
}

pub(crate) struct InventoryEntry {
    pub(crate) path: PathBuf,
    pub(crate) kind: InventoryEntryKind,
}

pub(crate) type InventoryDirectory = Box<dyn Iterator<Item = io::Result<InventoryEntry>>>;

pub(crate) struct InventoryRoot {
    path: PathBuf,
    #[cfg(unix)]
    directory: File,
}

impl InventoryRoot {
    #[cfg(unix)]
    pub(crate) fn verify_current_root(&self) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let original = self.directory.metadata()?;
        let current = std::fs::symlink_metadata(&self.path)?;
        if current.is_dir() && original.dev() == current.dev() && original.ino() == current.ino() {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Repository root changed during inventory; no snapshot was published",
        ))
    }

    #[cfg(not(unix))]
    pub(crate) fn verify_current_root(&self) -> io::Result<()> {
        if std::fs::symlink_metadata(&self.path)?.is_dir() {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Repository root changed during inventory; no snapshot was published",
        ))
    }

    pub(crate) fn new(canonical_root: &Path) -> io::Result<Self> {
        Ok(Self {
            path: canonical_root.to_owned(),
            #[cfg(unix)]
            directory: crate::bounded_file::open_absolute_directory_no_follow(canonical_root)?,
        })
    }

    #[cfg(unix)]
    fn open_directory(&self, path: &Path) -> io::Result<File> {
        let relative = crate::bounded_file::relative_path_within(&self.path, &self.path, path)?;
        let mut directory = self.directory.try_clone()?;
        for component in relative.components() {
            if let std::path::Component::Normal(name) = component {
                directory = crate::bounded_file::open_directory_at(&directory, name)?;
            }
        }
        Ok(directory)
    }

    #[cfg(unix)]
    pub(crate) fn open_file(&self, path: &Path) -> io::Result<File> {
        let (parent, name) = file_coordinates(path)?;
        crate::bounded_file::open_regular_at(&self.open_directory(parent)?, name)
    }

    /// Classify only an authenticated leaf. Unknown or unsafe paths still go
    /// through regular-file opening and retain its honest partial-result path.
    #[cfg(unix)]
    pub(crate) fn is_known_non_regular(&self, path: &Path) -> bool {
        self.leaf_kind(path)
            .is_ok_and(|kind| kind == InventoryEntryKind::Other)
    }

    #[cfg(unix)]
    fn leaf_kind(&self, path: &Path) -> io::Result<InventoryEntryKind> {
        use rustix::fs::{AtFlags, FileType};
        let (parent, name) = file_coordinates(path)?;
        let directory = self.open_directory(parent)?;
        let metadata = rustix::fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
        Ok(unix_kind(FileType::from_raw_mode(metadata.st_mode)))
    }

    // Other platforms retain strict partial results until leaf classification
    // can use the same pinned-ancestor guarantee as the Unix adapter.
    #[cfg(not(unix))]
    pub(crate) fn is_known_non_regular(&self, _path: &Path) -> bool {
        false
    }

    #[cfg(not(unix))]
    pub(crate) fn open_file(&self, path: &Path) -> io::Result<File> {
        crate::bounded_file::open_regular_file_within(&self.path, path)
    }

    #[cfg(unix)]
    pub(crate) fn read_directory(&self, path: &Path) -> io::Result<InventoryDirectory> {
        let directory = self.open_directory(path)?;
        let entries = rustix::fs::Dir::read_from(&directory)?;
        let parent = path.to_owned();
        Ok(Box::new(entries.filter_map(move |entry| {
            project_unix_entry(entry, &parent, &directory)
        })))
    }

    #[cfg(not(unix))]
    pub(crate) fn read_directory(&self, path: &Path) -> io::Result<InventoryDirectory> {
        let entries = crate::bounded_file::read_dir_within(&self.path, path)?;
        Ok(Box::new(entries.map(|entry| {
            let entry = entry?;
            Ok(InventoryEntry {
                path: entry.path(),
                kind: entry_kind(entry.file_type()?),
            })
        })))
    }
}

#[cfg(unix)]
fn file_coordinates(path: &Path) -> io::Result<(&Path, &std::ffi::OsStr)> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file parent is missing"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file name is missing"))?;
    Ok((parent, name))
}

#[cfg(not(unix))]
fn entry_kind(kind: std::fs::FileType) -> InventoryEntryKind {
    if kind.is_dir() {
        return InventoryEntryKind::Directory;
    }
    if kind.is_file() {
        InventoryEntryKind::File
    } else {
        InventoryEntryKind::Other
    }
}

#[cfg(unix)]
fn project_unix_entry(
    entry: rustix::io::Result<rustix::fs::DirEntry>,
    parent: &Path,
    directory: &File,
) -> Option<io::Result<InventoryEntry>> {
    match entry {
        Ok(entry) => project_unix_name(entry, parent, directory),
        Err(error) => Some(Err(error.into())),
    }
}

#[cfg(unix)]
fn project_unix_name(
    entry: rustix::fs::DirEntry,
    parent: &Path,
    directory: &File,
) -> Option<io::Result<InventoryEntry>> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = entry.file_name().to_bytes();
    if matches!(bytes, b"." | b"..") {
        return None;
    }
    let path = parent.join(std::ffi::OsStr::from_bytes(bytes));
    Some(unix_entry_kind(&entry, directory).map(|kind| InventoryEntry { path, kind }))
}

#[cfg(unix)]
fn unix_entry_kind(
    entry: &rustix::fs::DirEntry,
    directory: &File,
) -> io::Result<InventoryEntryKind> {
    use rustix::fs::{AtFlags, FileType};
    let mut kind = entry.file_type();
    if kind == FileType::Unknown {
        let metadata = rustix::fs::statat(directory, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)?;
        kind = FileType::from_raw_mode(metadata.st_mode);
    }
    Ok(unix_kind(kind))
}

#[cfg(unix)]
fn unix_kind(kind: rustix::fs::FileType) -> InventoryEntryKind {
    use rustix::fs::FileType;
    match kind {
        FileType::Directory => InventoryEntryKind::Directory,
        FileType::RegularFile => InventoryEntryKind::File,
        _ => InventoryEntryKind::Other,
    }
}

#[cfg(test)]
mod tests;
