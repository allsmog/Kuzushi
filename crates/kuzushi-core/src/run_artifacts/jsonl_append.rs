use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub(super) fn append_jsonl_line(path: &Path, line: &str) -> Result<()> {
    let mut file =
        open_append_file(path).with_context(|| format!("Could not open {}", path.display()))?;
    file.write_all(line.as_bytes())
        .with_context(|| format!("Could not write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("Could not fsync {}", path.display()))
}

pub(crate) fn append_run_artifact_jsonl_value(
    target: &Path,
    run_id: &str,
    leaf: &str,
    value: &Value,
) -> Result<PathBuf> {
    super::ensure_run_artifact_parent(target, run_id, leaf)?;
    let _guard = super::run_ledger::acquire_run_ledger_lock(target, run_id)?;
    let path = super::checked_run_artifact_path(target, run_id, leaf)?;
    reject_non_file_target(&path)?;
    let mut line = serde_json::to_string(value)?;
    line.push('\n');
    let existing_bytes = fs::symlink_metadata(&path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    anyhow::ensure!(
        existing_bytes.saturating_add(line.len() as u64)
            <= super::MAX_RUN_ARTIFACT_READ_BYTES as u64,
        "Run JSONL artifact exceeds {} bytes: {}",
        super::MAX_RUN_ARTIFACT_READ_BYTES,
        path.display()
    );
    append_jsonl_line(&path, &line)?;
    Ok(path)
}

fn reject_non_file_target(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!("Run JSONL target must not be a symlink: {}", path.display())
        }
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => anyhow::bail!("Run JSONL target is not a file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

#[cfg(unix)]
fn open_append_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_append_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new().create(true).append(true).open(path)
}
