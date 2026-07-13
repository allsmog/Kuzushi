mod fault;
mod file_state;
mod journal;
mod lease;
mod open_log;
mod recovery;
mod registry;
mod writer;

use self::journal::{AUDIT_LOCK_FILE, AUDIT_PENDING_FILE};
pub(super) use self::lease::{KwpAuditReservation, KwpAuditWriterLease};
#[cfg(test)]
use self::{fault::TestAuditFault, writer::record_for_body};
use super::KwpError;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone)]
struct AuditPaths {
    log: PathBuf,
    anchor: PathBuf,
    pending: PathBuf,
    lock: PathBuf,
}

impl AuditPaths {
    fn new(log: PathBuf, anchor: PathBuf) -> Self {
        Self {
            pending: log.with_file_name(AUDIT_PENDING_FILE),
            lock: log.with_file_name(AUDIT_LOCK_FILE),
            log,
            anchor,
        }
    }
}

fn lock_error(path: &Path, error: anyhow::Error) -> KwpError {
    KwpError::Internal(format!(
        "could not lock KWP audit log {}: {error}",
        path.display()
    ))
}

fn external_mutation(subject: &str) -> KwpError {
    KwpError::Internal(format!(
        "KWP {subject} changed outside the active audit writer"
    ))
}

#[cfg(test)]
fn injected_failure(stage: &str) -> KwpError {
    KwpError::Internal(format!("injected KWP audit failure after {stage}"))
}

fn append_error(path: &Path, error: std::io::Error) -> KwpError {
    KwpError::Internal(format!(
        "could not append KWP audit log {}: {error}",
        path.display()
    ))
}

fn sync_error(path: &Path, error: std::io::Error) -> KwpError {
    KwpError::Internal(format!(
        "could not sync KWP audit log {}: {error}",
        path.display()
    ))
}

pub(super) fn append_line(file: &mut std::fs::File, line: &[u8]) -> std::io::Result<()> {
    file.write_all(line)?;
    file.write_all(b"\n")
}

#[cfg(test)]
mod tests;
