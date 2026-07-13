use super::super::jsonl::{decode_bounded_jsonl_bytes, JsonlLimits};
use super::super::{
    ensure_jsonl_append_target, kwp_audit_log_integrity, path_exists_without_follow,
    read_anchored_kwp_audit_log, read_kwp_audit_anchor, write_kwp_audit_anchor, KwpAuditLogRecord,
    KwpError,
};
use super::fault::FaultInjector;
use super::journal::{clear_pending, read_pending, AuditIdentity, PendingAuditCommit};
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

pub(super) fn recover_or_read(
    identity: &AuditIdentity,
    log_path: &Path,
    anchor_path: &Path,
    pending_path: &Path,
    limits: JsonlLimits,
    fault: &mut FaultInjector,
) -> Result<Vec<KwpAuditLogRecord>, KwpError> {
    let Some(pending) = read_pending(pending_path, identity, limits)? else {
        return read_anchored_kwp_audit_log(log_path, anchor_path);
    };
    recover_pending(log_path, anchor_path, &pending, limits, fault)?;
    fault.fail_after_recovery_anchor()?;
    clear_pending(pending_path)?;
    read_anchored_kwp_audit_log(log_path, anchor_path)
}

fn recover_pending(
    log_path: &Path,
    anchor_path: &Path,
    pending: &PendingAuditCommit,
    limits: JsonlLimits,
    fault: &mut FaultInjector,
) -> Result<(), KwpError> {
    let bytes = read_log_bytes(log_path, limits)?;
    let prefix_len = usize::try_from(pending.prefix_bytes())
        .map_err(|_| invalid_recovery("prefix length is too large"))?;
    if bytes.len() < prefix_len {
        return Err(invalid_recovery("log is shorter than the journaled prefix"));
    }
    let (prefix, tail) = bytes.split_at(prefix_len);
    validate_prefix(prefix, log_path, pending, limits)?;
    ensure_journaled_tail(tail, &pending.transaction_bytes()?)?;
    validate_anchor_state(anchor_path, pending)?;
    rewrite_journaled_transaction(log_path, pending, fault)?;
    write_kwp_audit_anchor(
        anchor_path,
        pending.prefix_records()?.saturating_add(2),
        pending.recovery_marker().hash.clone(),
    )
}

fn validate_prefix(
    prefix: &[u8],
    log_path: &Path,
    pending: &PendingAuditCommit,
    limits: JsonlLimits,
) -> Result<(), KwpError> {
    ensure_prefix_boundary(prefix, pending.prefix_records()?)?;
    let records = decode_bounded_jsonl_bytes::<KwpAuditLogRecord>(prefix, log_path, limits)?;
    ensure_prefix_count(&records, pending.prefix_records()?)?;
    ensure_prefix_integrity(&records)?;
    ensure_prefix_hash(&records, pending.prefix_hash())
}

fn ensure_prefix_boundary(prefix: &[u8], records: usize) -> Result<(), KwpError> {
    if records > 0 && !prefix.ends_with(b"\n") {
        Err(invalid_recovery("journaled prefix ends inside a record"))
    } else {
        Ok(())
    }
}

fn ensure_prefix_count(records: &[KwpAuditLogRecord], expected: usize) -> Result<(), KwpError> {
    if records.len() == expected {
        Ok(())
    } else {
        Err(invalid_recovery("journaled prefix record count mismatch"))
    }
}

fn ensure_prefix_integrity(records: &[KwpAuditLogRecord]) -> Result<(), KwpError> {
    if kwp_audit_log_integrity(records)?.ok {
        Ok(())
    } else {
        Err(invalid_recovery("journaled prefix hash chain is invalid"))
    }
}

fn ensure_prefix_hash(
    records: &[KwpAuditLogRecord],
    expected: Option<&str>,
) -> Result<(), KwpError> {
    if records.last().map(|record| record.hash.as_str()) == expected {
        Ok(())
    } else {
        Err(invalid_recovery("journaled prefix tail hash mismatch"))
    }
}

fn ensure_journaled_tail(tail: &[u8], transaction: &[u8]) -> Result<(), KwpError> {
    if transaction.starts_with(tail) {
        Ok(())
    } else {
        Err(invalid_recovery(
            "log tail does not match the exact journaled transaction",
        ))
    }
}

fn validate_anchor_state(anchor_path: &Path, pending: &PendingAuditCommit) -> Result<(), KwpError> {
    if !path_exists_without_follow(anchor_path)? {
        return if pending.prefix_records()? == 0 {
            Ok(())
        } else {
            Err(invalid_recovery("journaled prefix anchor is missing"))
        };
    }
    let anchor = read_kwp_audit_anchor(anchor_path)?;
    let prefix_count = pending.prefix_records()? as u64;
    let allowed = (anchor.record_count == prefix_count
        && Some(anchor.last_hash.as_str()) == pending.prefix_hash())
        || (anchor.record_count == prefix_count + 1 && anchor.last_hash == pending.record().hash)
        || (anchor.record_count == prefix_count + 2
            && anchor.last_hash == pending.recovery_marker().hash);
    if allowed {
        Ok(())
    } else {
        Err(invalid_recovery(
            "anchor is outside the journaled transaction",
        ))
    }
}

fn read_log_bytes(path: &Path, limits: JsonlLimits) -> Result<Vec<u8>, KwpError> {
    if !path_exists_without_follow(path)? {
        return Ok(Vec::new());
    }
    crate::bounded_file::read_regular_bytes(path, limits.max_file_bytes()).map_err(|error| {
        KwpError::Internal(format!(
            "could not read KWP audit log {} for recovery: {error}",
            path.display()
        ))
    })
}

fn rewrite_journaled_transaction(
    path: &Path,
    pending: &PendingAuditCommit,
    fault: &mut FaultInjector,
) -> Result<(), KwpError> {
    ensure_jsonl_append_target(path, "audit.log")?;
    let mut file = open_recovery_file(path).map_err(|error| recovery_io(path, error))?;
    file.set_len(pending.prefix_bytes())
        .map_err(|error| recovery_io(path, error))?;
    file.seek(SeekFrom::Start(pending.prefix_bytes()))
        .map_err(|error| recovery_io(path, error))?;
    file.write_all(&pending.record_bytes()?)
        .map_err(|error| recovery_io(path, error))?;
    write_recovery_marker(path, &mut file, pending, fault)?;
    file.sync_all().map_err(|error| recovery_io(path, error))?;
    crate::fs_atomic::sync_parent_dir(path).map_err(|error| recovery_io(path, error))
}

fn write_recovery_marker(
    path: &Path,
    file: &mut fs::File,
    pending: &PendingAuditCommit,
    fault: &mut FaultInjector,
) -> Result<(), KwpError> {
    let mut marker = pending.recovery_line()?;
    marker.push(b'\n');
    if fault.take_recovery_marker_write() {
        let partial = marker.len().div_ceil(2);
        file.write_all(&marker[..partial])
            .map_err(|error| recovery_io(path, error))?;
        file.sync_all().map_err(|error| recovery_io(path, error))?;
        crate::fs_atomic::sync_parent_dir(path).map_err(|error| recovery_io(path, error))?;
        return Err(injected_failure("recovery-marker-write"));
    }
    file.write_all(&marker)
        .map_err(|error| recovery_io(path, error))
}

#[cfg(unix)]
fn open_recovery_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_recovery_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(path)
}

fn recovery_io(path: &Path, error: std::io::Error) -> KwpError {
    KwpError::Internal(format!(
        "could not recover KWP audit log {}: {error}",
        path.display()
    ))
}

fn injected_failure(stage: &str) -> KwpError {
    KwpError::Internal(format!("injected KWP audit failure after {stage}"))
}

fn invalid_recovery(reason: &str) -> KwpError {
    KwpError::Internal(format!("invalid KWP audit recovery state: {reason}"))
}
