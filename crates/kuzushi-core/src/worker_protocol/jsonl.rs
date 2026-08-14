mod reader;

pub(super) use reader::{decode_bounded_jsonl_bytes, read_bounded_jsonl, MissingFile};

use super::KwpError;
use serde::Serialize;
use std::fs::{self, File, Metadata};
use std::path::Path;

const JSONL_MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
const JSONL_MAX_RECORDS: usize = 4_096;
const JSONL_MAX_LINE_BYTES: usize = 64 * 1024;
const JSONL_MAX_DECODED_BYTES: u64 = 32 * 1024 * 1024;

pub(super) const AUDIT_JSONL_LIMITS: JsonlLimits = JsonlLimits::new("audit.log", "KWP audit log");
pub(super) const BUS_JSONL_LIMITS: JsonlLimits = JsonlLimits::new("bus.log", "KWP bus log");

#[derive(Clone, Copy)]
pub(super) struct JsonlLimits {
    resource: &'static str,
    label: &'static str,
    max_file_bytes: u64,
    max_records: usize,
    max_line_bytes: usize,
    max_decoded_bytes: u64,
}

impl JsonlLimits {
    const fn new(resource: &'static str, label: &'static str) -> Self {
        Self {
            resource,
            label,
            max_file_bytes: JSONL_MAX_FILE_BYTES,
            max_records: JSONL_MAX_RECORDS,
            max_line_bytes: JSONL_MAX_LINE_BYTES,
            max_decoded_bytes: JSONL_MAX_DECODED_BYTES,
        }
    }

    #[cfg(test)]
    pub(in crate::worker_protocol) const fn testing(
        resource: &'static str,
        max_file_bytes: u64,
        max_records: usize,
        max_line_bytes: usize,
        max_decoded_bytes: u64,
    ) -> Self {
        Self {
            resource,
            label: "JSONL log",
            max_file_bytes,
            max_records,
            max_line_bytes,
            max_decoded_bytes,
        }
    }

    fn quota(self, dimension: &str) -> KwpError {
        KwpError::quota(format!("{}.{dimension}", self.resource))
    }

    pub(super) fn max_line_bytes(self) -> usize {
        self.max_line_bytes
    }

    pub(super) fn max_file_bytes(self) -> usize {
        self.max_file_bytes as usize
    }
}

pub(super) fn serialize_bounded_jsonl<T: Serialize>(
    value: &T,
    limits: JsonlLimits,
) -> Result<Vec<u8>, KwpError> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        KwpError::Internal(format!("could not serialize JSONL record: {error}"))
    })?;
    if bytes.len() > limits.max_line_bytes {
        return Err(limits.quota("line.bytes"));
    }
    if bytes.len() as u64 > limits.max_decoded_bytes {
        return Err(limits.quota("decoded.bytes"));
    }
    Ok(bytes)
}

pub(super) fn ensure_jsonl_append_growth(
    current_bytes: u64,
    current_records: usize,
    line_bytes: usize,
    limits: JsonlLimits,
) -> Result<(), KwpError> {
    if current_records >= limits.max_records {
        return Err(limits.quota("records"));
    }
    if line_bytes > limits.max_line_bytes {
        return Err(limits.quota("line.bytes"));
    }
    let growth = (line_bytes as u64)
        .checked_add(1)
        .ok_or_else(|| limits.quota("bytes"))?;
    let next = current_bytes
        .checked_add(growth)
        .ok_or_else(|| limits.quota("bytes"))?;
    if next > limits.max_file_bytes {
        return Err(limits.quota("bytes"));
    }
    Ok(())
}

pub(super) fn verified_jsonl_file_len(
    file: &File,
    path: &Path,
    limits: JsonlLimits,
) -> Result<u64, KwpError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| read_error(path, error))?;
    ensure_regular_path(path, &path_metadata, limits)?;
    let handle_metadata = file.metadata().map_err(|error| read_error(path, error))?;
    ensure_same_file(path, &path_metadata, file, &handle_metadata, limits)?;
    ensure_file_size(handle_metadata.len(), limits)?;
    Ok(handle_metadata.len())
}

fn ensure_regular_path(
    path: &Path,
    metadata: &Metadata,
    limits: JsonlLimits,
) -> Result<(), KwpError> {
    if metadata.file_type().is_symlink() {
        return Err(KwpError::denied(format!("{}.symlink", limits.resource)));
    }
    if metadata.is_file() {
        Ok(())
    } else {
        Err(KwpError::Internal(format!(
            "JSONL target is not a file: {}",
            path.display()
        )))
    }
}

fn ensure_file_size(bytes: u64, limits: JsonlLimits) -> Result<(), KwpError> {
    if bytes > limits.max_file_bytes {
        Err(limits.quota("bytes"))
    } else {
        Ok(())
    }
}

fn ensure_same_file(
    path: &Path,
    path_metadata: &Metadata,
    handle: &File,
    handle_metadata: &Metadata,
    limits: JsonlLimits,
) -> Result<(), KwpError> {
    let same_file = same_file(path, path_metadata, handle, handle_metadata)
        .map_err(|error| read_error(path, error))?;
    if same_file {
        Ok(())
    } else {
        Err(KwpError::denied(format!("{}.identity", limits.resource)))
    }
}

#[cfg(unix)]
fn same_file(
    _path: &Path,
    path_metadata: &Metadata,
    _handle: &File,
    handle_metadata: &Metadata,
) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    Ok((path_metadata.dev(), path_metadata.ino())
        == (handle_metadata.dev(), handle_metadata.ino()))
}

#[cfg(windows)]
fn same_file(
    path: &Path,
    _path_metadata: &Metadata,
    handle: &File,
    _handle_metadata: &Metadata,
) -> std::io::Result<bool> {
    let path_file = super::open_fs_read_no_follow(path)?;
    Ok(crate::file_lock::windows_file_identity(&path_file)?
        == crate::file_lock::windows_file_identity(handle)?)
}

#[cfg(not(any(unix, windows)))]
fn same_file(
    _path: &Path,
    path_metadata: &Metadata,
    _handle: &File,
    handle_metadata: &Metadata,
) -> std::io::Result<bool> {
    Ok((path_metadata.len(), path_metadata.modified().ok())
        == (handle_metadata.len(), handle_metadata.modified().ok()))
}

fn read_error(path: &Path, error: std::io::Error) -> KwpError {
    KwpError::Internal(format!(
        "could not read JSONL log {}: {error}",
        path.display()
    ))
}

#[cfg(test)]
mod tests;
