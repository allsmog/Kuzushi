use super::super::jsonl::{JsonlLimits, AUDIT_JSONL_LIMITS};
use super::super::{kwp_audit_record_hash, KwpAuditLogBody, KwpAuditLogRecord, KwpError};
use super::fault::FaultInjector;
use super::journal::{pending_exists, write_pending, AuditIdentity, PendingAuditCommit};
use super::open_log::{AuditCheckpoint, OpenAuditLog};
use super::{external_mutation, AuditPaths};

pub(super) struct KwpAuditWriter {
    identity: AuditIdentity,
    paths: AuditPaths,
    pub(super) open: Option<OpenAuditLog>,
    limits: JsonlLimits,
    pub(super) fault: FaultInjector,
}

impl KwpAuditWriter {
    pub(super) fn new(identity: AuditIdentity, paths: AuditPaths) -> Self {
        Self {
            identity,
            paths,
            open: None,
            limits: AUDIT_JSONL_LIMITS,
            fault: FaultInjector::default(),
        }
    }

    pub(super) fn append_locked(&mut self, body: KwpAuditLogBody) -> Result<(), KwpError> {
        self.refresh()?;
        let pending = self.pending_for_body(body)?;
        write_pending(&self.paths.pending, &pending)?;
        self.fault.fail_after_pending()?;
        self.finish_pending(&pending)
    }

    pub(super) fn reserve_locked(
        &mut self,
        fallback: KwpAuditLogBody,
    ) -> Result<PendingAuditCommit, KwpError> {
        self.refresh()?;
        let open = self.open.as_ref().expect("audit writer initialized");
        open.ensure_reservation_capacity(self.limits)?;
        let pending = self.pending_for_body(fallback)?;
        write_pending(&self.paths.pending, &pending)?;
        self.fault.fail_after_pending()?;
        self.open
            .as_ref()
            .expect("audit writer initialized")
            .verify_unchanged(&self.paths)?;
        Ok(pending)
    }

    pub(super) fn replace_reserved_pending(
        &mut self,
        reserved: &PendingAuditCommit,
        body: KwpAuditLogBody,
    ) -> Result<PendingAuditCommit, KwpError> {
        self.verify_reserved_prefix(reserved)?;
        let record = record_for_body(body, reserved.prefix_hash().map(str::to_string))?;
        let actual = reserved.replace_record(&self.identity, record, self.limits)?;
        write_pending(&self.paths.pending, &actual)?;
        self.fault.fail_after_replacement()?;
        self.verify_reserved_prefix(&actual)?;
        Ok(actual)
    }

    pub(super) fn restore_pending(&self, pending: &PendingAuditCommit) -> Result<(), KwpError> {
        write_pending(&self.paths.pending, pending)
    }

    pub(super) fn finish_pending(&mut self, pending: &PendingAuditCommit) -> Result<(), KwpError> {
        self.verify_reserved_prefix(pending)?;
        self.open
            .as_mut()
            .expect("audit writer initialized")
            .finish_pending(&self.paths, pending, &mut self.fault)
    }

    pub(super) fn poison_after_error<T>(&mut self, result: &Result<T, KwpError>) {
        if result.is_err() {
            self.open = None;
        }
    }

    fn pending_for_body(&self, body: KwpAuditLogBody) -> Result<PendingAuditCommit, KwpError> {
        let open = self.open.as_ref().expect("audit writer initialized");
        let record = record_for_body(body, open.last_hash.clone())?;
        PendingAuditCommit::new(
            &self.identity,
            open.prefix_bytes(),
            open.record_count,
            open.last_hash.clone(),
            record,
            self.limits,
        )
    }

    fn verify_reserved_prefix(&self, pending: &PendingAuditCommit) -> Result<(), KwpError> {
        let open = self.open.as_ref().expect("audit writer initialized");
        let matches = open.prefix_bytes() == pending.prefix_bytes()
            && open.record_count == pending.prefix_records()?
            && open.last_hash.as_deref() == pending.prefix_hash();
        if matches {
            open.verify_unchanged(&self.paths)
        } else {
            Err(external_mutation("audit reserved prefix"))
        }
    }

    fn refresh(&mut self) -> Result<(), KwpError> {
        let has_pending = pending_exists(&self.paths.pending)?;
        if self.open.is_none() {
            return self.reopen(None);
        }
        let verify = self
            .open
            .as_ref()
            .expect("audit writer initialized")
            .verify_unchanged(&self.paths);
        if verify.is_ok() && !has_pending {
            return Ok(());
        }
        let checkpoint = self.open.as_ref().map(OpenAuditLog::checkpoint);
        match self.reopen(checkpoint.as_ref()) {
            Ok(()) => Ok(()),
            Err(_) if !has_pending => verify,
            Err(error) => Err(error),
        }
    }

    fn reopen(&mut self, checkpoint: Option<&AuditCheckpoint>) -> Result<(), KwpError> {
        let open = OpenAuditLog::open(
            &self.identity,
            &self.paths,
            checkpoint,
            self.limits,
            &mut self.fault,
        )?;
        self.open = Some(open);
        Ok(())
    }
}

pub(super) fn record_for_body(
    mut body: KwpAuditLogBody,
    prev: Option<String>,
) -> Result<KwpAuditLogRecord, KwpError> {
    body.prev = prev;
    let hash = kwp_audit_record_hash(&body)?;
    Ok(body.into_record(hash))
}
