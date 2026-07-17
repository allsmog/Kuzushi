use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

pub(super) fn write_pending_once(
    writer: &mut impl Write,
    body: &[u8],
    offset: &mut usize,
) -> std::io::Result<bool> {
    if *offset == body.len() {
        writer.flush()?;
        return Ok(true);
    }
    let written = writer.write(&body[*offset..])?;
    if written == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
    }
    *offset += written;
    Ok(false)
}

pub(super) fn create_secure_file(path: &Path) -> Result<File> {
    reject_existing_path(path)?;
    let mut options = OpenOptions::new();
    options.create_new(true).append(true).write(true);
    configure_secure_open(&mut options);
    options
        .open(path)
        .with_context(|| format!("could not create session transcript {}", path.display()))
}

pub(super) fn open_existing_secure_file(path: &Path) -> Result<File> {
    validate_regular_file(path)?;
    let mut options = OpenOptions::new();
    options.append(true).write(true);
    configure_secure_open(&mut options);
    options
        .open(path)
        .with_context(|| format!("could not reopen session transcript {}", path.display()))
}

fn reject_existing_path(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => anyhow::bail!("session transcript path already exists: {}", path.display()),
        Err(error) => Err(error).context("could not inspect session transcript path"),
    }
}

fn validate_regular_file(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "session transcript is a symlink"
    );
    anyhow::ensure!(
        metadata.is_file(),
        "session transcript is not a regular file"
    );
    Ok(())
}

#[cfg(unix)]
fn configure_secure_open(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn configure_secure_open(_options: &mut OpenOptions) {}
