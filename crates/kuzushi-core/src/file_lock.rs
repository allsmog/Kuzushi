//! Cross-process ownership for mutable `.kuzushi` ledgers.

use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::path::Path;

/// An exclusive advisory lock released automatically when the file is dropped.
///
/// The lock file is opened with `O_NOFOLLOW` on Unix so a repository-controlled
/// symlink cannot redirect the ownership boundary outside the intended state
/// directory.
pub(crate) struct ExclusiveFileLock {
    _file: File,
}

impl ExclusiveFileLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Could not create {}", parent.display()))?;
        }
        let file = open_lock_file(path)
            .with_context(|| format!("Could not open lock file {}", path.display()))?;
        file.lock()
            .with_context(|| format!("Could not lock {}", path.display()))?;
        Ok(Self { _file: file })
    }
}

#[cfg(unix)]
fn open_lock_file(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_lock_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
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
}
