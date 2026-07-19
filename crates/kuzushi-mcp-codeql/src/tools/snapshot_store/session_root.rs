use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const SESSION_PREFIX: &str = "session-";
const OWNER_LOCK: &str = "owner.lock";
const CLEANUP_LOCK: &str = ".cleanup.lock";
const MAX_SESSION_ROOTS: usize = 64;

pub(super) struct SnapshotSessionRoot {
    // Field order matters: the owner lock must remain held while TempDir drops.
    directory: TempDir,
    _owner: File,
}

impl SnapshotSessionRoot {
    pub(super) fn create(parent: &Path) -> Result<Self> {
        prepare_private_parent(parent)?;
        let coordinator = open_lock(&parent.join(CLEANUP_LOCK), false)?;
        coordinator
            .lock()
            .context("could not lock snapshot cleanup")?;
        cleanup_abandoned_sessions(parent)?;
        let directory = tempfile::Builder::new()
            .prefix(SESSION_PREFIX)
            .tempdir_in(parent)?;
        let owner = open_lock(&directory.path().join(OWNER_LOCK), true)?;
        owner.lock().context("could not lock snapshot session")?;
        Ok(Self {
            directory,
            _owner: owner,
        })
    }

    pub(super) fn path(&self) -> &Path {
        self.directory.path()
    }
}

fn cleanup_abandoned_sessions(parent: &Path) -> Result<()> {
    let mut sessions = abandoned_session_entries(parent)?;
    for entry in sessions.drain(..) {
        validate_session_entry(&entry)?;
        remove_if_abandoned(&entry)?;
    }
    Ok(())
}

fn abandoned_session_entries(parent: &Path) -> Result<Vec<std::fs::DirEntry>> {
    let mut sessions = Vec::new();
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(SESSION_PREFIX)
        {
            sessions.push(entry);
        }
        if sessions.len() > MAX_SESSION_ROOTS {
            break;
        }
    }
    anyhow::ensure!(
        sessions.len() <= MAX_SESSION_ROOTS,
        "too many retained CodeQL snapshot sessions; inspect {}",
        parent.display()
    );
    Ok(sessions)
}

fn validate_session_entry(entry: &std::fs::DirEntry) -> Result<()> {
    let metadata = std::fs::symlink_metadata(entry.path())?;
    ensure_not_reparse(&metadata, &entry.path())?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "refusing unsafe CodeQL snapshot entry {}",
        entry.path().display()
    );
    Ok(())
}

fn remove_if_abandoned(entry: &std::fs::DirEntry) -> Result<()> {
    let lock = open_lock(&entry.path().join(OWNER_LOCK), false)?;
    match lock.try_lock() {
        Ok(()) => std::fs::remove_dir_all(entry.path()).map_err(Into::into),
        Err(std::fs::TryLockError::WouldBlock) => Ok(()),
        Err(std::fs::TryLockError::Error(error)) => Err(error.into()),
    }
}

fn prepare_private_parent(parent: &Path) -> Result<()> {
    std::fs::create_dir_all(parent)?;
    let metadata = std::fs::symlink_metadata(parent)?;
    ensure_not_reparse(&metadata, parent)?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "CodeQL snapshot parent is not a regular directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        anyhow::ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "CodeQL snapshot parent is owned by another user"
        );
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn open_lock(path: &Path, create_new: bool) -> Result<File> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_not_reparse(&metadata, path)?;
            anyhow::ensure!(metadata.is_file(), "snapshot lock is not a regular file");
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .with_context(|| format!("could not open snapshot lock {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure_not_reparse(&metadata, path)?;
    anyhow::ensure!(metadata.is_file(), "snapshot lock is not a regular file");
    Ok(file)
}

#[cfg(windows)]
fn ensure_not_reparse(metadata: &std::fs::Metadata, path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    anyhow::ensure!(
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "refusing CodeQL snapshot reparse point {}",
        path.display()
    );
    Ok(())
}

#[cfg(not(windows))]
fn ensure_not_reparse(_metadata: &std::fs::Metadata, _path: &Path) -> Result<()> {
    Ok(())
}

pub(super) fn default_snapshot_parent() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        let suffix = unsafe { libc::geteuid() }.to_string();
        return Ok(std::env::temp_dir().join(format!("kuzushi-codeql-snapshots-v1-{suffix}")));
    }
    #[cfg(not(unix))]
    dirs::cache_dir()
        .map(|cache| cache.join("kuzushi/codeql-snapshots-v1"))
        .context("could not resolve operator cache directory for CodeQL snapshots")
}

#[cfg(test)]
pub(super) const TEST_OWNER_LOCK: &str = OWNER_LOCK;
#[cfg(test)]
pub(super) const TEST_SESSION_PREFIX: &str = SESSION_PREFIX;
#[cfg(all(test, windows))]
pub(super) fn open_lock_for_test(path: &Path) -> Result<File> {
    open_lock(path, false)
}
