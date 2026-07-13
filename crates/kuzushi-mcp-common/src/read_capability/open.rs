use super::ReadFileIdentity;
use anyhow::{Context, Result};
#[cfg(not(windows))]
use std::fs;
use std::fs::{File, Metadata};
use std::path::{Path, PathBuf};
#[cfg(any(unix, windows))]
use std::sync::Arc;
use std::time::UNIX_EPOCH;

#[cfg(windows)]
mod windows;

#[derive(Debug)]
pub(super) struct ReadRoot {
    pub(super) path: PathBuf,
    pub(super) requested_path: PathBuf,
    #[cfg(unix)]
    directory: Arc<File>,
    #[cfg(windows)]
    directory: Arc<File>,
    #[cfg(windows)]
    directory_identity: windows::WindowsFileIdentity,
}

impl Clone for ReadRoot {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            requested_path: self.requested_path.clone(),
            #[cfg(unix)]
            directory: Arc::clone(&self.directory),
            #[cfg(windows)]
            directory: Arc::clone(&self.directory),
            #[cfg(windows)]
            directory_identity: self.directory_identity,
        }
    }
}

impl ReadRoot {
    pub(super) fn new(root: &Path) -> Result<Self> {
        let requested_path = if root.is_absolute() {
            root.to_path_buf()
        } else {
            std::env::current_dir()?.join(root)
        };
        let path = std::fs::canonicalize(root)
            .with_context(|| format!("MCP read root does not exist: {}", root.display()))?;
        anyhow::ensure!(
            path.is_dir(),
            "MCP read root is not a directory: {}",
            path.display()
        );
        #[cfg(unix)]
        let directory = Arc::new(open_root_directory(&path)?);
        #[cfg(windows)]
        let directory = Arc::new(windows::open_root_directory(&path)?);
        #[cfg(windows)]
        let directory_identity = windows::file_identity(&directory)?;
        Ok(Self {
            path,
            requested_path,
            #[cfg(unix)]
            directory,
            #[cfg(windows)]
            directory,
            #[cfg(windows)]
            directory_identity,
        })
    }

    #[cfg(unix)]
    pub(super) fn clone_directory(&self) -> Result<File> {
        self.directory
            .try_clone()
            .context("could not clone retained MCP read-root handle")
    }
}

pub(super) fn identity_for(file: &File, metadata: &Metadata) -> Result<ReadFileIdentity> {
    #[cfg(unix)]
    let _ = file;
    let modified_nanos = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(ReadFileIdentity {
            len: metadata.len(),
            modified_nanos,
            device: metadata.dev(),
            inode: metadata.ino(),
            change_seconds: metadata.ctime(),
            change_nanos: metadata.ctime_nsec(),
            content_sha256: None,
        })
    }
    #[cfg(windows)]
    {
        let identity = windows::file_identity(file)?;
        let change_time = windows::file_change_time(file)?;
        Ok(ReadFileIdentity {
            len: metadata.len(),
            modified_nanos,
            volume_serial_number: identity.volume_serial_number,
            file_id: identity.file_id,
            change_time,
            content_sha256: None,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Ok(ReadFileIdentity {
            len: metadata.len(),
            modified_nanos,
            content_sha256: None,
        })
    }
}

#[cfg(unix)]
fn open_root_directory(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("could not open MCP read root: {}", path.display()))
}

#[cfg(unix)]
pub(super) fn open_file_beneath(root: &ReadRoot, path: &Path) -> Result<File> {
    let relative = path
        .strip_prefix(&root.path)
        .with_context(|| format!("path is outside the MCP read root: {}", path.display()))?;
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty() {
        return root.clone_directory();
    }
    let mut directory = root.directory.as_ref().try_clone()?;
    for (index, component) in components.iter().enumerate() {
        directory = open_next_component(directory, component, index + 1 == components.len(), path)?;
    }
    Ok(directory)
}

#[cfg(unix)]
pub(super) fn open_visible_directory(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| {
            format!(
                "could not reopen authorized MCP directory: {}",
                path.display()
            )
        })
}

#[cfg(unix)]
fn open_next_component(
    directory: File,
    component: &std::path::Component<'_>,
    is_leaf: bool,
    full_path: &Path,
) -> Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let std::path::Component::Normal(name) = component else {
        anyhow::bail!(
            "MCP path contains an invalid component: {}",
            full_path.display()
        );
    };
    let name = CString::new(name.as_bytes()).context("MCP path contains a NUL byte")?;
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | if is_leaf { 0 } else { libc::O_DIRECTORY };
    // SAFETY: `directory` is live, `name` is NUL-terminated, and the returned
    // descriptor is immediately transferred into `File` ownership.
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "could not open authorized MCP path: {}",
                full_path.display()
            )
        });
    }
    // SAFETY: `openat` returned a fresh owned descriptor on success.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(windows)]
pub(super) fn open_file_beneath(root: &ReadRoot, path: &Path) -> Result<File> {
    windows::open_file_beneath(root.directory.as_ref(), root.directory_identity, path)
}

#[cfg(windows)]
pub(super) fn open_visible_directory(path: &Path) -> Result<File> {
    windows::open_visible_directory(path)
}

#[cfg(not(any(unix, windows)))]
pub(super) fn open_file_beneath(_root: &ReadRoot, path: &Path) -> Result<File> {
    let metadata_before = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        !metadata_before.file_type().is_symlink(),
        "refusing to follow MCP symlink: {}",
        path.display()
    );
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    let opened = identity_for(&file, &opened_metadata)?;
    let current_file = File::open(path)?;
    let current_metadata = current_file.metadata()?;
    let current = identity_for(&current_file, &current_metadata)?;
    anyhow::ensure!(
        opened == current,
        "MCP file changed while it was being opened: {}",
        path.display()
    );
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
pub(super) fn open_visible_directory(path: &Path) -> Result<File> {
    File::open(path).with_context(|| {
        format!(
            "could not reopen authorized MCP directory: {}",
            path.display()
        )
    })
}
