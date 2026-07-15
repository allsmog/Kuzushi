use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const MAX_SESSION_FILE_BYTES: usize = 512 * 1024 * 1024;

pub(super) fn validate_session_id(session_id: &str) -> Result<()> {
    let parsed = Uuid::parse_str(session_id).context("session id must be a UUID")?;
    anyhow::ensure!(
        parsed.to_string() == session_id.to_ascii_lowercase(),
        "session id is not canonical"
    );
    Ok(())
}

pub(super) fn filename_has_session_id(path: &Path, session_id: &str) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(&format!("-{session_id}.jsonl")))
}

pub(super) fn read_safe_session_file(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "session transcript is a symlink"
    );
    anyhow::ensure!(
        metadata.is_file(),
        "session transcript is not a regular file"
    );
    anyhow::ensure!(
        metadata.len() <= MAX_SESSION_FILE_BYTES as u64,
        "session transcript exceeds the file limit"
    );
    let bytes = crate::bounded_file::read_regular_bytes(path, MAX_SESSION_FILE_BYTES)?;
    String::from_utf8(bytes).context("session transcript is not valid UTF-8")
}

pub(super) fn collect_session_files(root: &Path, depth: usize) -> Result<Vec<PathBuf>> {
    if depth == 0 {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(root)? {
        collect_entry(entry?, depth, &mut files)?;
    }
    Ok(files)
}

fn collect_entry(entry: fs::DirEntry, depth: usize, files: &mut Vec<PathBuf>) -> Result<()> {
    let path = entry.path();
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_dir() {
        files.extend(collect_session_files(&path, depth - 1)?);
        return Ok(());
    }
    if metadata.is_file() && is_session_filename(&path) {
        files.push(path);
    }
    Ok(())
}

fn is_session_filename(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("session-") && name.ends_with(".jsonl"))
}
