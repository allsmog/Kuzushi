use super::super::{KwpAuditLogBody, KwpError};
#[cfg(test)]
use super::fault::TestAuditFault;
use super::journal::PendingAuditCommit;
use super::registry::{acquire_writer, release_writer, AuditWriterKey};
use super::writer::KwpAuditWriter;
use super::{lock_error, AuditPaths};
use crate::file_lock::ExclusiveFileLock;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(5);

pub(in crate::worker_protocol) struct KwpAuditWriterLease {
    key: AuditWriterKey,
    pub(super) writer: Arc<Mutex<KwpAuditWriter>>,
    lock_path: PathBuf,
}

impl KwpAuditWriterLease {
    pub(in crate::worker_protocol) fn acquire(
        target: &Path,
        run_id: &str,
        log_path: PathBuf,
        anchor_path: PathBuf,
    ) -> Result<Self, KwpError> {
        let key = AuditWriterKey::new(target, run_id)?;
        let paths = AuditPaths::new(log_path, anchor_path);
        let writer = acquire_writer(&key, paths.clone())?;
        Ok(Self {
            key,
            writer,
            lock_path: paths.lock,
        })
    }

    #[cfg(test)]
    pub(in crate::worker_protocol) fn append(&self, body: KwpAuditLogBody) -> Result<(), KwpError> {
        let _lock = acquire_audit_lock(&self.lock_path)?;
        self.append_with_lock(body)
    }

    pub(in crate::worker_protocol) fn append_until(
        &self,
        body: KwpAuditLogBody,
        deadline: Instant,
        cancelled: impl FnMut() -> bool,
    ) -> Result<(), KwpError> {
        let _lock = acquire_audit_lock_until(&self.lock_path, deadline, cancelled)?;
        self.append_with_lock(body)
    }

    pub(in crate::worker_protocol) fn reserve_until(
        &self,
        fallback: KwpAuditLogBody,
        deadline: Instant,
        cancelled: impl FnMut() -> bool,
    ) -> Result<KwpAuditReservation, KwpError> {
        let lock = acquire_audit_lock_until(&self.lock_path, deadline, cancelled)?;
        let pending = {
            let mut writer = self.lock_writer()?;
            let result = writer.reserve_locked(fallback);
            writer.poison_after_error(&result);
            result?
        };
        Ok(KwpAuditReservation {
            writer: Arc::clone(&self.writer),
            _lock: lock,
            pending: Some(pending),
        })
    }

    fn append_with_lock(&self, body: KwpAuditLogBody) -> Result<(), KwpError> {
        let mut writer = self.lock_writer()?;
        let result = writer.append_locked(body);
        writer.poison_after_error(&result);
        result
    }

    fn lock_writer(&self) -> Result<std::sync::MutexGuard<'_, KwpAuditWriter>, KwpError> {
        self.writer
            .lock()
            .map_err(|_| KwpError::Internal("KWP audit writer was poisoned".to_string()))
    }

    #[cfg(test)]
    pub(super) fn inject_fault(&self, fault: TestAuditFault) {
        self.writer.lock().unwrap().fault.next = Some(fault);
    }
}

pub(in crate::worker_protocol) struct KwpAuditReservation {
    writer: Arc<Mutex<KwpAuditWriter>>,
    _lock: ExclusiveFileLock,
    pending: Option<PendingAuditCommit>,
}

impl KwpAuditReservation {
    pub(in crate::worker_protocol) fn commit(
        mut self,
        body: KwpAuditLogBody,
    ) -> Result<(), KwpError> {
        let fallback = self
            .pending
            .as_ref()
            .expect("audit reservation is active")
            .clone();
        let writer_handle = Arc::clone(&self.writer);
        let mut writer = writer_handle
            .lock()
            .map_err(|_| KwpError::Internal("KWP audit writer was poisoned".to_string()))?;
        let actual = match writer.replace_reserved_pending(&fallback, body) {
            Ok(actual) => actual,
            Err(error) => return self.restore_fallback(&mut writer, fallback, error),
        };
        self.pending = None;
        let result = writer.finish_pending(&actual);
        writer.poison_after_error(&result);
        result
    }

    fn restore_fallback(
        &mut self,
        writer: &mut KwpAuditWriter,
        fallback: PendingAuditCommit,
        error: KwpError,
    ) -> Result<(), KwpError> {
        if let Err(restore) = writer.restore_pending(&fallback) {
            self.pending = None;
            return Err(KwpError::Internal(format!(
                "{error}; could not restore fallback audit journal: {restore}"
            )));
        }
        Err(error)
    }
}

impl Drop for KwpAuditReservation {
    fn drop(&mut self) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        let Ok(mut writer) = self.writer.lock() else {
            return;
        };
        let result = writer.finish_pending(&pending);
        writer.poison_after_error(&result);
    }
}

impl Drop for KwpAuditWriterLease {
    fn drop(&mut self) {
        release_writer(&self.key, &self.writer);
    }
}

#[cfg(test)]
fn acquire_audit_lock(path: &Path) -> Result<ExclusiveFileLock, KwpError> {
    ExclusiveFileLock::acquire(path).map_err(|error| lock_error(path, error))
}

fn acquire_audit_lock_until(
    path: &Path,
    deadline: Instant,
    mut cancelled: impl FnMut() -> bool,
) -> Result<ExclusiveFileLock, KwpError> {
    loop {
        if let Some(lock) = try_audit_lock(path, deadline, &mut cancelled)? {
            return Ok(lock);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        std::thread::sleep(LOCK_RETRY_INTERVAL.min(remaining));
    }
}

fn try_audit_lock(
    path: &Path,
    deadline: Instant,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<Option<ExclusiveFileLock>, KwpError> {
    if Instant::now() >= deadline {
        return Err(KwpError::Deadline);
    }
    let lock = ExclusiveFileLock::try_acquire(path).map_err(|error| lock_error(path, error))?;
    if lock.is_some() {
        return Ok(lock);
    }
    if cancelled() {
        return Err(KwpError::NoActiveInvocation);
    }
    Ok(None)
}
