use super::super::jsonl::{ensure_jsonl_append_growth, JsonlLimits};
use super::super::{
    ensure_jsonl_append_target, kwp_audit_record_hash, serialize_kwp_audit_record, sha256_digest,
    AuditDecision, KwpAuditLogBody, KwpAuditLogRecord, KwpError,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub(super) const AUDIT_LOCK_FILE: &str = "kwp-audit.lock";
pub(super) const AUDIT_PENDING_FILE: &str = "kwp-audit.pending.json";
const PENDING_SCHEMA_VERSION: u32 = 1;
const MAX_PENDING_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub(super) struct AuditIdentity {
    target_sha256: String,
    run_id: String,
}

impl AuditIdentity {
    pub(super) fn new(target: &Path, run_id: &str) -> Self {
        Self {
            target_sha256: target_binding(target),
            run_id: run_id.to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PendingAuditCommit {
    schema_version: u32,
    target_sha256: String,
    run_id: String,
    prefix_bytes: u64,
    prefix_records: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prefix_hash: Option<String>,
    record_line_sha256: String,
    recovery_line_sha256: String,
    record: KwpAuditLogRecord,
    recovery_marker: KwpAuditLogRecord,
}

impl PendingAuditCommit {
    pub(super) fn new(
        identity: &AuditIdentity,
        prefix_bytes: u64,
        prefix_records: usize,
        prefix_hash: Option<String>,
        record: KwpAuditLogRecord,
        limits: JsonlLimits,
    ) -> Result<Self, KwpError> {
        let recovery_marker = recovery_marker_for(&record)?;
        let record_line = serialize_kwp_audit_record(&record)?;
        let recovery_line = serialize_kwp_audit_record(&recovery_marker)?;
        let pending = Self {
            schema_version: PENDING_SCHEMA_VERSION,
            target_sha256: identity.target_sha256.clone(),
            run_id: identity.run_id.clone(),
            prefix_bytes,
            prefix_records: prefix_records as u64,
            prefix_hash,
            record_line_sha256: sha256_digest(&record_line).0,
            recovery_line_sha256: sha256_digest(&recovery_line).0,
            record,
            recovery_marker,
        };
        pending.validate(identity, limits)?;
        Ok(pending)
    }

    pub(super) fn replace_record(
        &self,
        identity: &AuditIdentity,
        record: KwpAuditLogRecord,
        limits: JsonlLimits,
    ) -> Result<Self, KwpError> {
        Self::new(
            identity,
            self.prefix_bytes,
            self.prefix_records()?,
            self.prefix_hash.clone(),
            record,
            limits,
        )
    }

    pub(super) fn validate(
        &self,
        identity: &AuditIdentity,
        limits: JsonlLimits,
    ) -> Result<(), KwpError> {
        validate_header(self, identity)?;
        validate_prefix(self)?;
        validate_records(self)?;
        ensure_transaction_capacity(self, limits)
    }

    pub(super) fn record_line(&self) -> Result<Vec<u8>, KwpError> {
        verified_line(&self.record, &self.record_line_sha256, "record")
    }

    pub(super) fn recovery_line(&self) -> Result<Vec<u8>, KwpError> {
        verified_line(
            &self.recovery_marker,
            &self.recovery_line_sha256,
            "recovery marker",
        )
    }

    pub(super) fn transaction_bytes(&self) -> Result<Vec<u8>, KwpError> {
        let record = self.record_line()?;
        let marker = self.recovery_line()?;
        let mut bytes = Vec::with_capacity(record.len() + marker.len() + 2);
        bytes.extend_from_slice(&record);
        bytes.push(b'\n');
        bytes.extend_from_slice(&marker);
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub(super) fn record_bytes(&self) -> Result<Vec<u8>, KwpError> {
        let mut bytes = self.record_line()?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub(super) fn record(&self) -> &KwpAuditLogRecord {
        &self.record
    }

    pub(super) fn recovery_marker(&self) -> &KwpAuditLogRecord {
        &self.recovery_marker
    }

    pub(super) fn prefix_bytes(&self) -> u64 {
        self.prefix_bytes
    }

    pub(super) fn prefix_records(&self) -> Result<usize, KwpError> {
        usize::try_from(self.prefix_records)
            .map_err(|_| invalid_pending("record count is too large"))
    }

    pub(super) fn prefix_hash(&self) -> Option<&str> {
        self.prefix_hash.as_deref()
    }
}

pub(super) fn write_pending(path: &Path, pending: &PendingAuditCommit) -> Result<(), KwpError> {
    ensure_jsonl_append_target(path, "audit.pending")?;
    let mut bytes = serde_json::to_vec(pending)
        .map_err(|error| invalid_pending(&format!("could not serialize: {error}")))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_PENDING_BYTES {
        return Err(KwpError::quota("audit.pending.bytes"));
    }
    crate::fs_atomic::write_atomic_bytes(path, &bytes).map_err(|error| {
        KwpError::Internal(format!(
            "could not persist KWP audit pending commit {}: {error}",
            path.display()
        ))
    })
}

pub(super) fn read_pending(
    path: &Path,
    identity: &AuditIdentity,
    limits: JsonlLimits,
) -> Result<Option<PendingAuditCommit>, KwpError> {
    if !pending_exists(path)? {
        return Ok(None);
    }
    let body = crate::bounded_file::read_utf8_text(path, MAX_PENDING_BYTES).map_err(|error| {
        KwpError::Internal(format!(
            "could not read KWP audit pending commit {}: {error}",
            path.display()
        ))
    })?;
    let pending = serde_json::from_str::<PendingAuditCommit>(&body)
        .map_err(|error| invalid_pending(&format!("could not parse: {error}")))?;
    pending.validate(identity, limits)?;
    Ok(Some(pending))
}

pub(super) fn pending_exists(path: &Path) -> Result<bool, KwpError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(KwpError::denied("audit.pending")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(KwpError::Internal(format!(
            "could not inspect KWP audit pending commit {}: {error}",
            path.display()
        ))),
    }
}

pub(super) fn clear_pending(path: &Path) -> Result<(), KwpError> {
    if !pending_exists(path)? {
        return Ok(());
    }
    fs::remove_file(path).map_err(|error| {
        KwpError::Internal(format!(
            "could not clear KWP audit pending commit {}: {error}",
            path.display()
        ))
    })?;
    crate::fs_atomic::sync_parent_dir(path).map_err(|error| {
        KwpError::Internal(format!(
            "could not sync KWP audit pending commit dir {}: {error}",
            path.display()
        ))
    })
}

fn validate_header(pending: &PendingAuditCommit, identity: &AuditIdentity) -> Result<(), KwpError> {
    if pending.schema_version != PENDING_SCHEMA_VERSION {
        return Err(invalid_pending("unsupported schema version"));
    }
    if pending.target_sha256 != identity.target_sha256 {
        return Err(invalid_pending("target binding mismatch"));
    }
    if pending.run_id != identity.run_id
        || pending.record.run_id.0 != identity.run_id
        || pending.recovery_marker.run_id.0 != identity.run_id
    {
        return Err(invalid_pending("run binding mismatch"));
    }
    Ok(())
}

fn validate_prefix(pending: &PendingAuditCommit) -> Result<(), KwpError> {
    let count = pending.prefix_records()?;
    if count == 0 && pending.prefix_hash.is_some() {
        return Err(invalid_pending("empty prefix has a hash"));
    }
    if count > 0 && pending.prefix_hash.is_none() {
        return Err(invalid_pending("non-empty prefix has no hash"));
    }
    if pending.record.prev.as_deref() != pending.prefix_hash.as_deref() {
        return Err(invalid_pending("record does not extend the bound prefix"));
    }
    Ok(())
}

fn validate_records(pending: &PendingAuditCommit) -> Result<(), KwpError> {
    validate_record_hash(&pending.record, "record")?;
    validate_record_hash(&pending.recovery_marker, "recovery marker")?;
    if pending.recovery_marker != recovery_marker_for(&pending.record)? {
        return Err(invalid_pending("recovery marker binding mismatch"));
    }
    pending.record_line()?;
    pending.recovery_line()?;
    Ok(())
}

fn validate_record_hash(record: &KwpAuditLogRecord, label: &str) -> Result<(), KwpError> {
    let expected = kwp_audit_record_hash(&record.body_for_hash())?;
    if expected == record.hash {
        Ok(())
    } else {
        Err(invalid_pending(&format!("{label} hash mismatch")))
    }
}

fn verified_line(
    record: &KwpAuditLogRecord,
    expected_digest: &str,
    label: &str,
) -> Result<Vec<u8>, KwpError> {
    let line = serialize_kwp_audit_record(record)?;
    if sha256_digest(&line).0 == expected_digest {
        Ok(line)
    } else {
        Err(invalid_pending(&format!("{label} line digest mismatch")))
    }
}

fn ensure_transaction_capacity(
    pending: &PendingAuditCommit,
    limits: JsonlLimits,
) -> Result<(), KwpError> {
    let record = pending.record_line()?;
    let marker = pending.recovery_line()?;
    let records = pending.prefix_records()?;
    ensure_jsonl_append_growth(pending.prefix_bytes, records, record.len(), limits)?;
    let after_record = pending.prefix_bytes + record.len() as u64 + 1;
    ensure_jsonl_append_growth(after_record, records + 1, marker.len(), limits)
}

fn recovery_marker_for(record: &KwpAuditLogRecord) -> Result<KwpAuditLogRecord, KwpError> {
    let body = KwpAuditLogBody {
        ts_ms: record.ts_ms,
        run_id: record.run_id.clone(),
        invocation_id: record.invocation_id.clone(),
        module_id: record.module_id.clone(),
        digest: record.digest.clone(),
        event: "audit.recovery".to_string(),
        decision: AuditDecision::Allow,
        detail: serde_json::json!({ "recoveredHash": record.hash }),
        prev: Some(record.hash.clone()),
    };
    let hash = kwp_audit_record_hash(&body)?;
    Ok(body.into_record(hash))
}

fn invalid_pending(reason: &str) -> KwpError {
    KwpError::Internal(format!("invalid KWP audit pending commit: {reason}"))
}

mod identity;

use self::identity::target_binding;
