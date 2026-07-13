use super::{external_mutation, KwpError};
use std::fs::{self, File, Metadata};
use std::path::Path;

#[cfg(windows)]
use crate::file_lock::windows_file_identity;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AuditFileState {
    pub(super) length: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(windows)]
    volume_serial_number: Option<u32>,
    #[cfg(windows)]
    file_index: Option<u64>,
    #[cfg(windows)]
    last_write_time: u64,
    #[cfg(not(any(unix, windows)))]
    modified: Option<std::time::SystemTime>,
}

impl AuditFileState {
    pub(super) fn for_open_path(file: &File, path: &Path) -> Result<Self, KwpError> {
        let path_metadata = fs::symlink_metadata(path).map_err(|error| {
            KwpError::Internal(format!(
                "could not inspect KWP audit log {}: {error}",
                path.display()
            ))
        })?;
        if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
            return Err(KwpError::denied("audit.log"));
        }
        reject_windows_reparse_path(path, &path_metadata)?;
        let handle_metadata = file.metadata().map_err(|error| {
            KwpError::Internal(format!(
                "could not inspect open KWP audit log {}: {error}",
                path.display()
            ))
        })?;
        let path_state = path_file_state(path, &path_metadata)?;
        let handle_state = Self::from_open_file(file, &handle_metadata, path)?;
        if path_state != handle_state {
            return Err(external_mutation("audit log path"));
        }
        Ok(handle_state)
    }

    #[cfg(unix)]
    fn from_open_file(_file: &File, metadata: &Metadata, _path: &Path) -> Result<Self, KwpError> {
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            length: metadata.len(),
            device: metadata.dev(),
            inode: metadata.ino(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }

    #[cfg(windows)]
    fn from_open_file(file: &File, metadata: &Metadata, path: &Path) -> Result<Self, KwpError> {
        use std::os::windows::fs::MetadataExt;
        let identity = windows_file_identity(file).map_err(|error| identity_error(path, error))?;
        Ok(Self {
            length: metadata.len(),
            volume_serial_number: Some(identity.volume_serial_number),
            file_index: Some(identity.file_index),
            last_write_time: metadata.last_write_time(),
        })
    }

    #[cfg(not(any(unix, windows)))]
    fn from_open_file(_file: &File, metadata: &Metadata, _path: &Path) -> Result<Self, KwpError> {
        Ok(Self {
            length: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

#[cfg(windows)]
fn path_file_state(path: &Path, metadata: &Metadata) -> Result<AuditFileState, KwpError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| identity_error(path, error))?;
    AuditFileState::from_open_file(&file, metadata, path)
}

#[cfg(not(windows))]
fn path_file_state(path: &Path, metadata: &Metadata) -> Result<AuditFileState, KwpError> {
    let file = File::open(path).map_err(|error| identity_error(path, error))?;
    AuditFileState::from_open_file(&file, metadata, path)
}

#[cfg(windows)]
fn reject_windows_reparse_path(_path: &Path, metadata: &Metadata) -> Result<(), KwpError> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        Ok(())
    } else {
        Err(KwpError::denied("audit.log.reparse"))
    }
}

#[cfg(not(windows))]
fn reject_windows_reparse_path(_path: &Path, _metadata: &Metadata) -> Result<(), KwpError> {
    Ok(())
}

fn identity_error(path: &Path, error: std::io::Error) -> KwpError {
    KwpError::Internal(format!(
        "could not verify KWP audit log identity {}: {error}",
        path.display()
    ))
}
