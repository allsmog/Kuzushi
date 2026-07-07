use crate::event_log::{EventEnvelope, EventKind};
use anyhow::Result;
use rusqlite::{params, Transaction};

use super::projection_payload::{payload_str, require_payload_str};
use super::sql_seq;

pub(super) fn project_audit_event(tx: &Transaction<'_>, event: &EventEnvelope) -> Result<()> {
    if !is_audit_event(event.event_kind) {
        return Ok(());
    }
    tx.execute(
        r#"
        insert into audit_events(
          event_hash, seq, event_kind, actor, run_id, stable_fp,
          subject, summary, payload_json, created_at
        )
        values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        on conflict(event_hash) do nothing
        "#,
        params![
            event.event_hash.as_str(),
            sql_seq(event.seq)?,
            event.event_kind.as_str(),
            event.actor,
            event.run_id.as_deref(),
            payload_str(&event.payload, "stableFp"),
            payload_str(&event.payload, "subject"),
            require_payload_str(&event.payload, "summary")?,
            event.payload.to_string(),
            event.created_at,
        ],
    )?;
    Ok(())
}

fn is_audit_event(event_kind: EventKind) -> bool {
    matches!(
        event_kind,
        EventKind::DiagnosticRecorded
            | EventKind::ModelCallRecorded
            | EventKind::PluginInvocationRecorded
    )
}
