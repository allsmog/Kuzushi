use super::super::jsonl::{ensure_jsonl_append_growth, JsonlLimits};
use super::super::{
    ensure_jsonl_append_target, ensure_kwp_audit_parent, open_jsonl_append,
    path_exists_without_follow, read_kwp_audit_anchor, write_kwp_audit_anchor, KwpAuditLogRecord,
    KwpError,
};
use super::fault::FaultInjector;
use super::file_state::AuditFileState;
use super::journal::{clear_pending, AuditIdentity, PendingAuditCommit};
use super::recovery::recover_or_read;
use super::{append_error, append_line, external_mutation, sync_error, AuditPaths};
use std::fs::File;
use std::path::Path;

#[derive(Clone)]
pub(super) struct AuditCheckpoint {
    record_count: usize,
    last_hash: Option<String>,
}

pub(super) struct OpenAuditLog {
    file: File,
    pub(super) record_count: usize,
    pub(super) last_hash: Option<String>,
    file_state: AuditFileState,
    #[cfg(test)]
    pub(super) initial_records_read: usize,
    #[cfg(test)]
    pub(super) initial_bytes_read: u64,
}

impl OpenAuditLog {
    pub(super) fn open(
        identity: &AuditIdentity,
        paths: &AuditPaths,
        checkpoint: Option<&AuditCheckpoint>,
        limits: JsonlLimits,
        fault: &mut FaultInjector,
    ) -> Result<Self, KwpError> {
        #[cfg(test)]
        let initial_bytes_read = existing_file_len(&paths.log)?;
        let records = recover_or_read(
            identity,
            &paths.log,
            &paths.anchor,
            &paths.pending,
            limits,
            fault,
        )?;
        validate_extension(&records, checkpoint)?;
        ensure_kwp_audit_parent(&paths.log)?;
        ensure_jsonl_append_target(&paths.log, "audit.log")?;
        let file = open_jsonl_append(&paths.log).map_err(|error| open_error(&paths.log, error))?;
        let file_state = AuditFileState::for_open_path(&file, &paths.log)?;
        Ok(Self {
            file,
            record_count: records.len(),
            last_hash: records.last().map(|record| record.hash.clone()),
            file_state,
            #[cfg(test)]
            initial_records_read: records.len(),
            #[cfg(test)]
            initial_bytes_read,
        })
    }

    pub(super) fn checkpoint(&self) -> AuditCheckpoint {
        AuditCheckpoint {
            record_count: self.record_count,
            last_hash: self.last_hash.clone(),
        }
    }

    pub(super) fn verify_unchanged(&self, paths: &AuditPaths) -> Result<(), KwpError> {
        let current = AuditFileState::for_open_path(&self.file, &paths.log)?;
        if current != self.file_state {
            return Err(external_mutation("audit log"));
        }
        match (&self.last_hash, self.record_count) {
            (None, 0) if !path_exists_without_follow(&paths.anchor)? => Ok(()),
            (Some(last_hash), count) => verify_anchor(&paths.anchor, count, last_hash),
            _ => Err(external_mutation("audit tail")),
        }
    }

    pub(super) fn ensure_reservation_capacity(&self, limits: JsonlLimits) -> Result<(), KwpError> {
        ensure_jsonl_append_growth(
            self.file_state.length,
            self.record_count,
            limits.max_line_bytes(),
            limits,
        )?;
        let next_bytes = self.file_state.length + limits.max_line_bytes() as u64 + 1;
        ensure_jsonl_append_growth(
            next_bytes,
            self.record_count + 1,
            limits.max_line_bytes(),
            limits,
        )
    }

    pub(super) fn finish_pending(
        &mut self,
        paths: &AuditPaths,
        pending: &PendingAuditCommit,
        fault: &mut FaultInjector,
    ) -> Result<(), KwpError> {
        self.verify_unchanged(paths)?;
        let line = pending.record_line()?;
        append_and_sync(&mut self.file, &paths.log, &line)?;
        fault.fail_after_record()?;
        let next_count = self.record_count.saturating_add(1);
        write_kwp_audit_anchor(&paths.anchor, next_count, pending.record().hash.clone())?;
        fault.fail_after_anchor()?;
        clear_pending(&paths.pending)?;
        self.advance(paths, pending.record(), next_count)
    }

    pub(super) fn prefix_bytes(&self) -> u64 {
        self.file_state.length
    }

    fn advance(
        &mut self,
        paths: &AuditPaths,
        record: &KwpAuditLogRecord,
        next_count: usize,
    ) -> Result<(), KwpError> {
        self.file_state = AuditFileState::for_open_path(&self.file, &paths.log)?;
        self.record_count = next_count;
        self.last_hash = Some(record.hash.clone());
        Ok(())
    }
}

fn validate_extension(
    records: &[KwpAuditLogRecord],
    checkpoint: Option<&AuditCheckpoint>,
) -> Result<(), KwpError> {
    let Some(checkpoint) = checkpoint else {
        return Ok(());
    };
    if checkpoint.record_count == 0 {
        return Ok(());
    }
    let preserved = records
        .get(checkpoint.record_count - 1)
        .is_some_and(|record| Some(record.hash.as_str()) == checkpoint.last_hash.as_deref());
    if records.len() > checkpoint.record_count && preserved {
        Ok(())
    } else {
        Err(external_mutation("audit history"))
    }
}

fn append_and_sync(file: &mut File, path: &Path, line: &[u8]) -> Result<(), KwpError> {
    append_line(file, line).map_err(|error| append_error(path, error))?;
    file.sync_all().map_err(|error| sync_error(path, error))?;
    crate::fs_atomic::sync_parent_dir(path).map_err(|error| {
        KwpError::Internal(format!(
            "could not sync KWP audit dir {}: {error}",
            path.display()
        ))
    })
}

fn verify_anchor(path: &Path, record_count: usize, last_hash: &str) -> Result<(), KwpError> {
    let anchor = read_kwp_audit_anchor(path)?;
    if anchor.record_count == record_count as u64 && anchor.last_hash == last_hash {
        Ok(())
    } else {
        Err(external_mutation("audit anchor"))
    }
}

fn open_error(path: &Path, error: std::io::Error) -> KwpError {
    KwpError::Internal(format!(
        "could not open KWP audit log {}: {error}",
        path.display()
    ))
}

#[cfg(test)]
fn existing_file_len(path: &Path) -> Result<u64, KwpError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(KwpError::denied("audit.symlink")),
        Ok(metadata) if metadata.is_file() => Ok(metadata.len()),
        Ok(_) => Err(KwpError::Internal(format!(
            "KWP audit path is not a file: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(KwpError::Internal(format!(
            "could not inspect KWP audit log {}: {error}",
            path.display()
        ))),
    }
}
