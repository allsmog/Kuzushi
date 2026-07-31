use super::*;
use crate::event_log::EventKind;
use crate::storage_v3::writer_actor::{
    AuditWrite, DecisionCommand, StorageWriterActor, WriterCommand,
};
use serde_json::Value;

impl FindingStore {
    pub fn record_finding_audit_event(
        &self,
        finding_id: i64,
        actor: impl Into<String>,
        subject: impl Into<String>,
        summary: impl Into<String>,
        details: Value,
    ) -> Result<()> {
        let Some(target) = self.v3_target_for_finding(finding_id, "finding audit event")? else {
            return Ok(());
        };
        StorageWriterActor::commit_blocking(
            target.event_log_dir,
            target.db_path,
            WriterCommand::Decision(DecisionCommand::RecordAudit(AuditWrite {
                event_kind: EventKind::DiagnosticRecorded,
                actor: actor.into(),
                run_id: None,
                stable_fp: Some(target.stable_fp),
                subject: Some(subject.into()),
                summary: summary.into(),
                details,
            })),
        )?;
        Ok(())
    }

    /// Audit events recorded against a finding for one subject, oldest first.
    /// Mirrors `list_static_proof_history`'s identity-then-query shape.
    pub fn list_finding_audit_events(
        &self,
        finding_id: i64,
        subject: &str,
    ) -> Result<Vec<FindingAuditEvent>> {
        let Some(identity) = self.finding_identity_for_id(finding_id, "finding audit events")?
        else {
            return Ok(Vec::new());
        };
        let mut stmt = self.conn.prepare(
            r#"
            select seq, actor, subject, summary, payload_json, created_at
              from audit_events
             where stable_fp = ?1 and subject = ?2
             order by seq asc
            "#,
        )?;
        let rows = stmt.query_map(params![identity.stable_fp(), subject], audit_event_row)?;
        rows.map(|row| row.map_err(anyhow::Error::from))
            .collect::<Result<Vec<_>>>()
            .context("Could not list finding audit events")
    }
}

/// A projected `audit_events` row for one finding, with `details` split out of
/// the stored payload.
#[derive(Debug, Clone, PartialEq)]
pub struct FindingAuditEvent {
    pub seq: i64,
    pub actor: String,
    pub subject: String,
    pub summary: String,
    pub details: Value,
    pub created_at: String,
}

fn audit_event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FindingAuditEvent> {
    let payload: String = row.get(4)?;
    Ok(FindingAuditEvent {
        seq: row.get(0)?,
        actor: row.get(1)?,
        subject: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
        summary: row.get(3)?,
        details: audit_event_details(&payload),
        created_at: row.get(5)?,
    })
}

fn audit_event_details(payload: &str) -> Value {
    serde_json::from_str::<Value>(payload)
        .ok()
        .and_then(|value| value.get("details").cloned())
        .unwrap_or(Value::Null)
}
