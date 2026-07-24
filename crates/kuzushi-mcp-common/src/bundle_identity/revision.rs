use anyhow::Result;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

#[derive(Debug, Eq, PartialEq)]
pub(super) struct DirectoryRevision {
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
    pub(super) fn read(path: &Path, label: &str) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "{label} directory changed type: {}",
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
pub(super) fn encoded_name(name: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    name.as_bytes().to_vec()
}

#[cfg(windows)]
pub(super) fn encoded_name(name: &OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    name.encode_wide().flat_map(u16::to_le_bytes).collect()
}

#[cfg(not(any(unix, windows)))]
pub(super) fn encoded_name(name: &OsStr) -> Vec<u8> {
    name.to_string_lossy().into_owned().into_bytes()
}
