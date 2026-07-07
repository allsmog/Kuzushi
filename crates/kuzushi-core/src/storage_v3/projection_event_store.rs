use crate::event_log::EventEnvelope;
use anyhow::{Context, Result};
use rusqlite::params;

use super::projection_payload::stable_fp_from_payload;
use super::sql_seq;

pub(super) fn insert_event_row(
    tx: &rusqlite::Transaction<'_>,
    event: &EventEnvelope,
) -> Result<()> {
    tx.execute(
        "insert or replace into finding_events(
           event_hash, seq, stable_fp, event_kind, payload_json, actor, created_at
         ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            event.event_hash.as_str(),
            sql_seq(event.seq)?,
            stable_fp_from_payload(&event.payload),
            event.event_kind.as_str(),
            serde_json::to_string(&event.payload)
                .context("Could not serialize projection event payload")?,
            event.actor,
            event.created_at,
        ],
    )?;
    Ok(())
}

pub(super) fn clear_projection_tables(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    tx.execute_batch(
        r#"
        delete from patch_attempt_events;
        delete from audit_events;
        delete from verification_events;
        delete from run_states;
        delete from run_events;
        delete from review_decisions;
        delete from rekey_edges;
        delete from stable_findings;
        delete from finding_observations;
        delete from attack_surface_snapshots;
        delete from file_deletions;
        delete from indexed_files;
        delete from blobs;
        delete from target_snapshots;
        delete from finding_events;
        delete from finding_search_content;
        "#,
    )
    .context("Could not clear projection tables")
}
