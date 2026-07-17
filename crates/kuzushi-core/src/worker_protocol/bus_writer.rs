use super::jsonl::{
    ensure_jsonl_append_growth, read_bounded_jsonl, serialize_bounded_jsonl,
    verified_jsonl_file_len, MissingFile, BUS_JSONL_LIMITS,
};
use super::{ensure_jsonl_append_target, open_jsonl_append, KwpBusEvent, KwpError};
use crate::file_lock::ExclusiveFileLock;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const BUS_PAYLOAD_MAX_BYTES: usize = 48 * 1024;

pub(super) fn append_bounded_bus_event(path: &Path, event: &KwpBusEvent) -> Result<(), KwpError> {
    ensure_bus_parent(path)?;
    let _lock = acquire_bus_lock(path)?;
    ensure_jsonl_append_target(path, "bus.log")?;
    let existing = read_bounded_jsonl::<KwpBusEvent>(path, BUS_JSONL_LIMITS, MissingFile::Empty)?;
    ensure_bus_payload_fits(event)?;
    let line = serialize_bounded_jsonl(event, BUS_JSONL_LIMITS)?;
    let mut file = open_jsonl_append(path).map_err(|error| open_error(path, error))?;
    let current_bytes = verified_jsonl_file_len(&file, path, BUS_JSONL_LIMITS)?;
    ensure_jsonl_append_growth(current_bytes, existing.len(), line.len(), BUS_JSONL_LIMITS)?;
    append_line(&mut file, &line).map_err(|error| append_error(path, error))?;
    file.sync_all().map_err(|error| sync_error(path, error))?;
    crate::fs_atomic::sync_parent_dir(path).map_err(|error| sync_error(path, error))
}

fn ensure_bus_payload_fits(event: &KwpBusEvent) -> Result<(), KwpError> {
    let bytes = serde_json::to_vec(&event.payload)
        .map_err(|error| KwpError::Internal(format!("could not serialize bus payload: {error}")))?;
    if bytes.len() > BUS_PAYLOAD_MAX_BYTES {
        Err(KwpError::quota("bus.payload.bytes"))
    } else {
        Ok(())
    }
}

fn ensure_bus_parent(path: &Path) -> Result<(), KwpError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    fs::create_dir_all(parent).map_err(|error| {
        KwpError::Internal(format!(
            "could not create KWP bus dir {}: {error}",
            parent.display()
        ))
    })
}

fn acquire_bus_lock(path: &Path) -> Result<ExclusiveFileLock, KwpError> {
    ExclusiveFileLock::acquire(&bus_lock_path(path)).map_err(|error| {
        KwpError::Internal(format!(
            "could not lock KWP bus log {}: {error}",
            path.display()
        ))
    })
}

fn bus_lock_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("kwp-bus.jsonl"));
    name.push(".lock");
    path.with_file_name(name)
}

fn append_line(file: &mut fs::File, line: &[u8]) -> std::io::Result<()> {
    let mut record = Vec::with_capacity(line.len().saturating_add(1));
    record.extend_from_slice(line);
    record.push(b'\n');
    file.write_all(&record)
}

fn open_error(path: &Path, error: std::io::Error) -> KwpError {
    KwpError::Internal(format!(
        "could not open KWP bus log {}: {error}",
        path.display()
    ))
}

fn append_error(path: &Path, error: std::io::Error) -> KwpError {
    KwpError::Internal(format!(
        "could not append KWP bus log {}: {error}",
        path.display()
    ))
}

fn sync_error(path: &Path, error: impl std::fmt::Display) -> KwpError {
    KwpError::Internal(format!(
        "could not sync KWP bus log {}: {error}",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker_protocol::{Digest, InvocationId, ModuleId, RunId};
    use serde_json::Value;

    #[test]
    fn payload_boundary_succeeds_and_limit_plus_one_fails() {
        let mut event = event_with_payload(Value::String("x".repeat(BUS_PAYLOAD_MAX_BYTES - 2)));
        assert!(ensure_bus_payload_fits(&event).is_ok());

        event.payload = Value::String("x".repeat(BUS_PAYLOAD_MAX_BYTES - 1));
        assert_eq!(
            ensure_bus_payload_fits(&event).unwrap_err(),
            KwpError::quota("bus.payload.bytes")
        );
    }

    fn event_with_payload(payload: Value) -> KwpBusEvent {
        KwpBusEvent {
            ts_ms: 1,
            run_id: RunId("run".to_string()),
            invocation_id: InvocationId("invocation".to_string()),
            module_id: ModuleId("module".to_string()),
            digest: Digest("sha256:test".to_string()),
            topic: "topic".to_string(),
            payload,
        }
    }
}
