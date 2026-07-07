use crate::event_log::{EventEnvelope, EventKind};
use anyhow::Result;
use rusqlite::{params, Transaction};

use super::projection_payload::{payload_i64, payload_str, require_payload_str};
use super::sql_seq;

pub(super) fn project_run_lifecycle_event(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<()> {
    if !is_run_lifecycle_event(event.event_kind) {
        return Ok(());
    }
    insert_run_event(tx, event)?;
    fold_run_state(tx, event)
}

fn insert_run_event(tx: &Transaction<'_>, event: &EventEnvelope) -> Result<()> {
    tx.execute(
        r#"
        insert into run_events(
          event_hash, seq, run_id, event_kind, target, status,
          findings_count, actor, created_at, payload_json
        )
        values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        on conflict(event_hash) do nothing
        "#,
        params![
            event.event_hash.as_str(),
            sql_seq(event.seq)?,
            require_payload_str(&event.payload, "runId")?,
            event.event_kind.as_str(),
            payload_str(&event.payload, "target"),
            require_payload_str(&event.payload, "status")?,
            payload_i64(&event.payload, "findingsCount"),
            event.actor,
            event.created_at,
            event.payload.to_string(),
        ],
    )?;
    Ok(())
}

fn fold_run_state(tx: &Transaction<'_>, event: &EventEnvelope) -> Result<()> {
    let run_id = require_payload_str(&event.payload, "runId")?;
    let event_seq = sql_seq(event.seq)?;
    let started_seq = (event.event_kind == EventKind::RunStarted).then_some(event_seq);
    let completed_seq = matches!(
        event.event_kind,
        EventKind::RunCompleted | EventKind::RunFailed
    )
    .then_some(event_seq);
    tx.execute(
        r#"
        insert into run_states(
          run_id, target, status, findings_count, started_seq,
          completed_seq, updated_seq, updated_at
        )
        values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        on conflict(run_id) do update set
          target = coalesce(excluded.target, run_states.target),
          status = excluded.status,
          findings_count = coalesce(excluded.findings_count, run_states.findings_count),
          started_seq = coalesce(run_states.started_seq, excluded.started_seq),
          completed_seq = coalesce(excluded.completed_seq, run_states.completed_seq),
          updated_seq = excluded.updated_seq,
          updated_at = excluded.updated_at
        "#,
        params![
            run_id,
            payload_str(&event.payload, "target"),
            require_payload_str(&event.payload, "status")?,
            payload_i64(&event.payload, "findingsCount"),
            started_seq,
            completed_seq,
            event_seq,
            event.created_at,
        ],
    )?;
    Ok(())
}

fn is_run_lifecycle_event(event_kind: EventKind) -> bool {
    matches!(
        event_kind,
        EventKind::RunStarted | EventKind::RunCompleted | EventKind::RunFailed
    )
}
