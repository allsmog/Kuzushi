use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub fn read_bounded_file(path: &Path, max_bytes: usize) -> Result<Option<Vec<u8>>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("could not inspect {}", path.display()))
        }
    };
    ensure_regular_nonsymlink(path, &metadata)?;
    anyhow::ensure!(
        metadata.len() <= max_bytes as u64,
        "cache file exceeds the {max_bytes}-byte limit: {}",
        path.display()
    );
    let mut file = open_read_nofollow(path)?;
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(max_bytes));
    Read::by_ref(&mut file)
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= max_bytes,
        "cache file exceeds the {max_bytes}-byte limit: {}",
        path.display()
    );
    Ok(Some(bytes))
}

pub fn write_atomic_file(path: &Path, bytes: &[u8], max_bytes: usize) -> Result<()> {
    anyhow::ensure!(
        bytes.len() <= max_bytes,
        "cache output exceeds the {max_bytes}-byte limit"
    );
    let parent = path.parent().context("cache path has no parent")?;
    ensure_private_directory(parent)?;
    reject_existing_link(path)?;
    let temporary = temporary_path(path)?;
    let mut cleanup = TemporaryFile::create(&temporary)?;
    cleanup.file.write_all(bytes)?;
    cleanup.file.sync_all()?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("could not atomically replace {}", path.display()))?;
    cleanup.keep = true;
    Ok(())
}

pub fn ensure_private_directory(path: &Path) -> Result<()> {
    if let Err(error) = std::fs::create_dir_all(path) {
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error).with_context(|| format!("could not create {}", path.display()));
        }
    }
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "cache directory is not a real directory: {}",
        path.display()
    );
    #[cfg(unix)]
    set_private_permissions(path)?;
    Ok(())
}

fn ensure_regular_nonsymlink(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "cache path is not a regular no-follow file: {}",
        path.display()
    );
    Ok(())
}

fn reject_existing_link(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => ensure_regular_nonsymlink(path, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("could not inspect {}", path.display())),
    }
}

fn temporary_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .context("cache file has no name")?
        .to_string_lossy();
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Ok(path.with_file_name(format!(".{name}.{}.{}.tmp", std::process::id(), sequence)))
}

struct TemporaryFile {
    path: PathBuf,
    file: File,
    keep: bool,
}

impl TemporaryFile {
    fn create(path: &Path) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let file = options.open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            keep: false,
        })
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn open_read_nofollow(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .with_context(|| format!("could not open {}", path.display()))
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}
