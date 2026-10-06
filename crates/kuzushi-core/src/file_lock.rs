//! Cross-process ownership for mutable `.kuzushi` ledgers.

use anyhow::{Context, Result};
use std::fs::File;
use std::path::Path;

/// An exclusive advisory lock released automatically when the file is dropped.
///
/// The lock file is opened with `O_NOFOLLOW` on Unix so a repository-controlled
/// symlink cannot redirect the ownership boundary outside the intended state
/// directory.
pub(crate) struct ExclusiveFileLock {
    _file: File,
}

/// A shared advisory lock released automatically when the file is dropped.
/// Multiple immutable readers may coexist; an exclusive writer waits until
/// every reader has finished.
pub(crate) struct SharedFileLock {
    _file: File,
}

impl Drop for ExclusiveFileLock {
    fn drop(&mut self) {
        let _ = self._file.unlock();
    }
}

impl Drop for SharedFileLock {
    fn drop(&mut self) {
        let _ = self._file.unlock();
    }
}

impl ExclusiveFileLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self> {
        let file = prepared_lock_file(path)?;
        file.lock()
            .with_context(|| format!("Could not lock {}", path.display()))?;
        Ok(Self { _file: file })
    }

    pub(crate) fn acquire_cancellable(path: &Path, canceled: &dyn Fn() -> bool) -> Result<Self> {
        anyhow::ensure!(!canceled(), "lock acquisition was canceled");
        let file = prepared_lock_file(path)?;
        loop {
            anyhow::ensure!(!canceled(), "lock acquisition was canceled");
            if try_lock_file(&file, path)? {
                anyhow::ensure!(!canceled(), "lock acquisition was canceled");
                return Ok(Self { _file: file });
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    pub(crate) fn try_acquire(path: &Path) -> Result<Option<Self>> {
        let file = prepared_lock_file(path)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(error)) => {
                Err(error).with_context(|| format!("Could not lock {}", path.display()))
            }
        }
    }
}

fn try_lock_file(file: &File, path: &Path) -> Result<bool> {
    match file.try_lock() {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(std::fs::TryLockError::Error(error)) => {
            Err(error).with_context(|| format!("Could not lock {}", path.display()))
        }
    }
}

impl SharedFileLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self> {
        let file = prepared_lock_file(path)?;
        file.lock_shared()
            .with_context(|| format!("Could not read-lock {}", path.display()))?;
        Ok(Self { _file: file })
    }
}

fn prepared_lock_file(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    open_lock_file(path).with_context(|| format!("Could not open lock file {}", path.display()))
}

#[cfg(unix)]
fn open_lock_file(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
fn open_lock_file(path: &Path) -> std::io::Result<File> {
    reject_windows_reparse_components(path)?;
    let file = create_windows_lock_file(path)?;
    verify_windows_lock_identity(&file, path)?;
    Ok(file)
}

#[cfg(windows)]
fn create_windows_lock_file(path: &Path) -> std::io::Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS,
    };

    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "lock path contains a NUL code unit",
        ));
    }
    wide.push(0);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(windows)]
fn verify_windows_lock_identity(file: &File, path: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    let path_metadata = std::fs::symlink_metadata(path)?;
    let handle_metadata = file.metadata()?;
    reject_windows_reparse_attributes(path, path_metadata.file_attributes())?;
    reject_windows_reparse_attributes(path, handle_metadata.file_attributes())?;
    let path_file = create_windows_lock_file(path)?;
    reject_windows_reparse_attributes(path, path_file.metadata()?.file_attributes())?;
    let identity_changed = windows_file_identity(&path_file)? != windows_file_identity(file)?;
    let final_path_changed = windows_final_path(&path_file)? != windows_final_path(file)?;
    if identity_changed || final_path_changed {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("lock path identity changed: {}", path.display()),
        ));
    }
    reject_windows_reparse_components(path)
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WindowsFileIdentity {
    pub(crate) volume_serial_number: u32,
    pub(crate) file_index: u64,
}

#[cfg(windows)]
pub(crate) fn windows_file_identity(file: &File) -> std::io::Result<WindowsFileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let succeeded = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) };
    if succeeded == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(WindowsFileIdentity {
        volume_serial_number: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

#[cfg(windows)]
pub(crate) fn windows_final_path(file: &File) -> std::io::Result<std::path::PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
    };
    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    let required =
        unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), std::ptr::null_mut(), 0, flags) };
    if required == 0 || required as usize > 32_768 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buffer = vec![0_u16; required as usize + 1];
    let written = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            flags,
        )
    };
    if written == 0 || written as usize >= buffer.len() {
        return Err(std::io::Error::last_os_error());
    }
    buffer.truncate(written as usize);
    Ok(std::path::PathBuf::from(OsString::from_wide(&buffer)))
}

#[cfg(windows)]
fn reject_windows_reparse_components(path: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    for prefix in windows_lock_component_paths(path) {
        match std::fs::symlink_metadata(&prefix) {
            Ok(metadata) => reject_windows_reparse_attributes(&prefix, metadata.file_attributes())?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn windows_lock_component_paths(path: &Path) -> impl Iterator<Item = std::path::PathBuf> + '_ {
    use std::path::{Component, PathBuf};

    path.components()
        .scan(PathBuf::new(), |prefix, component| {
            prefix.push(component.as_os_str());
            Some((component, prefix.clone()))
        })
        .filter_map(|(component, prefix)| {
            (!matches!(component, Component::Prefix(_))).then_some(prefix)
        })
}

#[cfg(windows)]
fn reject_windows_reparse_attributes(path: &Path, attributes: u32) -> std::io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("refusing to follow lock reparse point {}", path.display()),
        ))
    }
}

#[cfg(not(any(unix, windows)))]
fn open_lock_file(path: &Path) -> std::io::Result<File> {
    std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn serializes_independent_file_descriptors() {
        let temp = tempfile::tempdir().unwrap();
        let path = Arc::new(temp.path().join("state.lock"));
        let barrier = Arc::new(Barrier::new(2));
        let first_path = Arc::clone(&path);
        let first_barrier = Arc::clone(&barrier);
        let first = std::thread::spawn(move || {
            let guard = ExclusiveFileLock::acquire(&first_path).unwrap();
            first_barrier.wait();
            std::thread::sleep(std::time::Duration::from_millis(100));
            drop(guard);
        });
        barrier.wait();
        let started = std::time::Instant::now();
        let second = ExclusiveFileLock::acquire(&path).unwrap();
        assert!(started.elapsed() >= std::time::Duration::from_millis(75));
        drop(second);
        first.join().unwrap();
    }

    #[test]
    fn an_exclusive_writer_waits_for_shared_readers() {
        let temp = tempfile::tempdir().unwrap();
        let path = Arc::new(temp.path().join("state.lock"));
        let barrier = Arc::new(Barrier::new(2));
        let reader_path = Arc::clone(&path);
        let reader_barrier = Arc::clone(&barrier);
        let reader = std::thread::spawn(move || {
            let guard = SharedFileLock::acquire(&reader_path).unwrap();
            reader_barrier.wait();
            std::thread::sleep(std::time::Duration::from_millis(100));
            drop(guard);
        });
        barrier.wait();
        let started = std::time::Instant::now();
        let writer = ExclusiveFileLock::acquire(&path).unwrap();
        assert!(started.elapsed() >= std::time::Duration::from_millis(75));
        drop(writer);
        reader.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_lock_target() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        std::fs::write(&outside, "outside").unwrap();
        let link = temp.path().join("state.lock");
        symlink(&outside, &link).unwrap();

        assert!(ExclusiveFileLock::acquire(&link).is_err());
        assert_eq!(std::fs::read_to_string(outside).unwrap(), "outside");
    }

    #[cfg(windows)]
    #[test]
    fn windows_lock_component_paths_keep_complete_roots_and_every_child() {
        for root in [r"\\?\C:\", r"\\?\UNC\server\share\"] {
            let root = std::path::PathBuf::from(root);
            let parent = root.join("state");
            let leaf = parent.join("ledger.lock");
            let paths = windows_lock_component_paths(&leaf).collect::<Vec<_>>();
            assert_eq!(paths, [root, parent, leaf]);
        }
    }

    #[cfg(windows)]
    #[test]
    fn canonicalized_windows_lock_paths_support_exclusive_and_shared_guards() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.lock");
        drop(ExclusiveFileLock::acquire(&path).unwrap());
        let canonical = std::fs::canonicalize(path).unwrap();
        assert!(canonical.to_string_lossy().starts_with(r"\\?\"));
        drop(ExclusiveFileLock::acquire(&canonical).unwrap());
        drop(SharedFileLock::acquire(&canonical).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_reparse_attributes() {
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        let error = reject_windows_reparse_attributes(
            Path::new("state.lock"),
            FILE_ATTRIBUTE_REPARSE_POINT,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(reject_windows_reparse_attributes(Path::new("state.lock"), 0).is_ok());
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };

    #[test]
    fn cancellation_releases_a_waiting_owner_without_stealing_the_held_lock() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("owner.lock");
        let owner = ExclusiveFileLock::acquire(&path).unwrap();
        let canceled = Arc::new(AtomicBool::new(false));
        let checks = Arc::new(AtomicUsize::new(0));
        let flag = Arc::clone(&canceled);
        let observed = Arc::clone(&checks);
        let waiting = path.clone();
        let worker = std::thread::spawn(move || {
            ExclusiveFileLock::acquire_cancellable(&waiting, &|| {
                observed.fetch_add(1, Ordering::SeqCst);
                flag.load(Ordering::SeqCst)
            })
            .err()
            .unwrap()
            .to_string()
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while checks.load(Ordering::SeqCst) < 3 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(checks.load(Ordering::SeqCst) >= 3);
        canceled.store(true, Ordering::SeqCst);
        assert!(worker.join().unwrap().contains("canceled"));
        assert!(ExclusiveFileLock::try_acquire(&path).unwrap().is_none());
        drop(owner);
        drop(ExclusiveFileLock::acquire_cancellable(&path, &|| false).unwrap());
    }

    #[test]
    fn already_canceled_lock_request_does_not_create_a_lock_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("unused.lock");
        assert!(ExclusiveFileLock::acquire_cancellable(&path, &|| true).is_err());
        assert!(!path.exists());
    }
}
