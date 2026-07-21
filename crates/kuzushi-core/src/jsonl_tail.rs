//! Torn-tail healing for append-only JSONL ledgers.
//!
//! Every well-formed append ends with `\n`, so a newline-less tail is
//! exactly one `write` interrupted by a killed process. Left in place it
//! poisons strict re-readers on the append path (each future append fails
//! forever), so single-writer appenders truncate it under their exclusive
//! ledger lock before validating or appending. A tail longer than the
//! ledger's per-line bound is corruption, not a torn append, and is
//! refused so real damage stays an explicit error.

use anyhow::{Context, Result};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Truncate a torn, newline-less tail from an already-open ledger file.
/// The handle must be readable and writable (append handles opened with
/// `read(true)` qualify; `set_len` does not require write position).
pub(crate) fn heal_torn_jsonl_tail(
    file: &mut fs::File,
    path: &Path,
    max_line_bytes: usize,
    label: &str,
) -> Result<()> {
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(());
    }
    let window = (max_line_bytes as u64).saturating_add(1).min(len);
    let start = len - window;
    file.seek(SeekFrom::Start(start))?;
    let mut tail = Vec::with_capacity(window as usize);
    Read::by_ref(file).take(window).read_to_end(&mut tail)?;
    if tail.last() == Some(&b'\n') {
        return Ok(());
    }
    let keep = match tail.iter().rposition(|byte| *byte == b'\n') {
        Some(position) => start + position as u64 + 1,
        None if start == 0 => 0,
        None => anyhow::bail!(
            "{label} {} ends in an oversized newline-less tail; refusing to truncate",
            path.display()
        ),
    };
    crate::runtime_diagnostics::record_runtime_diagnostic(
        "jsonl",
        format!(
            "truncating {} torn tail byte(s) from {} (previous writer died mid-append)",
            len - keep,
            path.display()
        ),
    );
    file.set_len(keep)
        .with_context(|| format!("Could not truncate torn tail of {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("Could not fsync {}", path.display()))?;
    Ok(())
}

/// Open `path` (if it exists) and heal a torn tail in place. A missing
/// ledger is a clean no-op; symlinks are refused like every other ledger
/// open in this crate.
pub(crate) fn heal_torn_jsonl_tail_at(
    path: &Path,
    max_line_bytes: usize,
    label: &str,
) -> Result<()> {
    let mut file = match open_rw_no_follow(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("Could not open {}", path.display()))
        }
    };
    heal_torn_jsonl_tail(&mut file, path, max_line_bytes, label)
}

#[cfg(unix)]
fn open_rw_no_follow(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_rw_no_follow(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new().read(true).write(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LABEL: &str = "Test ledger";

    #[test]
    fn heals_a_newline_less_tail_back_to_the_last_complete_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.jsonl");
        fs::write(&path, "{\"a\":1}\n{\"b\":2}\n{\"tor").unwrap();

        heal_torn_jsonl_tail_at(&path, 1024, LABEL).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"a\":1}\n{\"b\":2}\n");
    }

    #[test]
    fn clean_missing_and_empty_ledgers_are_no_ops() {
        let dir = tempfile::tempdir().unwrap();
        let clean = dir.path().join("clean.jsonl");
        fs::write(&clean, "{\"a\":1}\n").unwrap();
        let empty = dir.path().join("empty.jsonl");
        fs::write(&empty, "").unwrap();

        heal_torn_jsonl_tail_at(&clean, 1024, LABEL).unwrap();
        heal_torn_jsonl_tail_at(&empty, 1024, LABEL).unwrap();
        heal_torn_jsonl_tail_at(&dir.path().join("missing.jsonl"), 1024, LABEL).unwrap();

        assert_eq!(fs::read_to_string(&clean).unwrap(), "{\"a\":1}\n");
        assert_eq!(fs::read_to_string(&empty).unwrap(), "");
    }

    #[test]
    fn a_whole_file_torn_tail_truncates_to_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.jsonl");
        fs::write(&path, "{\"only-partial").unwrap();

        heal_torn_jsonl_tail_at(&path, 1024, LABEL).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "");
    }

    #[test]
    fn an_oversized_newline_less_tail_is_refused_as_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.jsonl");
        let mut body = String::from("{\"a\":1}\n");
        body.push_str(&"x".repeat(64));
        fs::write(&path, &body).unwrap();

        let error = heal_torn_jsonl_tail_at(&path, 16, LABEL)
            .unwrap_err()
            .to_string();

        assert!(error.contains("oversized newline-less tail"), "{error}");
        assert_eq!(fs::read_to_string(&path).unwrap(), body);
    }
}
