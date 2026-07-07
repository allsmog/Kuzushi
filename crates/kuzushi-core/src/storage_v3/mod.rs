use crate::event_log::EventEnvelope;
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeSet;
use std::path::Path;

mod projection_projectors;
mod projection_audit;
mod projection_event_store;
mod projection_finding_lifecycle;
mod projection_fts;
mod projection_observations;
mod projection_payload;
mod projection_proof;
mod projection_review;
mod projection_rekey;
mod projection_runs;
mod projection_schema;
pub mod writer_actor;

use projection_event_store::{clear_projection_tables, insert_event_row};
use projection_fts::rebuild_fts_if_available;
use projection_projectors::apply_projection_event;
use projection_rekey::{
    forwarded_rekey_target, reject_rekey_cycle, rekey_event_hash_after, ProjectionEventRow,
};
use projection_schema::{FTS_SCHEMA, PROJECTION_SCHEMA};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionMeta {
    pub applied_seq: u64,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionApplyReceipt {
    pub review_decision_id: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StalenessPolicy {
    AllowStale,
    RejectStale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadOptions {
    pub min_seq: Option<u64>,
    pub staleness: StalenessPolicy,
}

impl ReadOptions {
    pub fn allow_stale() -> Self {
        Self {
            min_seq: None,
            staleness: StalenessPolicy::AllowStale,
        }
    }

    pub fn require_min_seq(min_seq: u64) -> Self {
        Self {
            min_seq: Some(min_seq),
            staleness: StalenessPolicy::RejectStale,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionRead<T> {
    pub applied_seq: u64,
    pub generation: u64,
    pub rows: T,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableFindingRead {
    pub stable_fp: String,
    pub current_status: String,
    pub canonical_severity: String,
    pub canonical_title: String,
    pub canonical_path: Option<String>,
    pub first_seen_seq: u64,
    pub last_seen_seq: u64,
    pub last_observation_hash: Option<String>,
}

pub struct ProjectionDb {
    conn: Connection,
}

impl ProjectionDb {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Could not create {}", parent.display()))?;
        }
        let conn =
            Connection::open(path).with_context(|| format!("Could not open {}", path.display()))?;
        configure_projection_connection(&conn)?;
        create_projection_schema(&conn)?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("Could not open in-memory v3 projection")?;
        configure_projection_connection(&conn)?;
        create_projection_schema(&conn)?;
        Ok(Self { conn })
    }

    pub fn meta(&self) -> Result<ProjectionMeta> {
        Ok(ProjectionMeta {
            applied_seq: meta_u64(&self.conn, "applied_seq")?,
            generation: meta_u64(&self.conn, "generation")?,
        })
    }

    pub fn set_applied_seq(&self, applied_seq: u64) -> Result<()> {
        let tx = self
            .conn
            .unchecked_transaction()
            .context("Could not open projection watermark transaction")?;
        set_meta_u64(&tx, "applied_seq", applied_seq)?;
        tx.commit()
            .context("Could not commit projection watermark transaction")
    }

    pub fn apply_event(&self, event: &EventEnvelope) -> Result<ProjectionApplyReceipt> {
        let tx = self
            .conn
            .unchecked_transaction()
            .context("Could not open projection event transaction")?;
        insert_event_row(&tx, event)?;
        let review_decision_id = apply_projection_event(&tx, event)?;
        set_meta_u64(&tx, "applied_seq", event.seq)?;
        tx.commit()
            .context("Could not commit projection event transaction")?;
        Ok(ProjectionApplyReceipt { review_decision_id })
    }

    pub fn reset_for_rebuild(&self) -> Result<ProjectionMeta> {
        let tx = self
            .conn
            .unchecked_transaction()
            .context("Could not open projection rebuild transaction")?;
        let next_generation = meta_u64(&tx, "generation")?.saturating_add(1);
        clear_projection_tables(&tx)?;
        set_meta_u64(&tx, "applied_seq", 0)?;
        set_meta_u64(&tx, "generation", next_generation)?;
        rebuild_fts_if_available(&tx)?;
        tx.commit()
            .context("Could not commit projection rebuild reset")?;
        self.meta()
    }

    pub fn event_seqs_for_stable_fp_after(
        &self,
        stable_fp: &str,
        watermark: u64,
    ) -> Result<Vec<u64>> {
        let mut stmt = self.conn.prepare(
            "select seq from finding_events
              where stable_fp = ?1 and seq > ?2
              order by seq asc",
        )?;
        let rows = stmt.query_map(params![stable_fp, sql_watermark(watermark)?], |row| {
            sqlite_seq(row, 0)
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not load intervening finding events")
    }

    pub fn safe_rekey_target_after(
        &self,
        stable_fp: &str,
        watermark: u64,
    ) -> Result<Option<String>> {
        let mut current = stable_fp.to_string();
        let mut seen = BTreeSet::new();
        loop {
            reject_rekey_cycle(stable_fp, &current, &mut seen)?;
            let events = self.events_for_stable_fp_after(&current, watermark)?;
            let Some(event_hash) = rekey_event_hash_after(&current, watermark, &events)? else {
                return Ok(forwarded_rekey_target(stable_fp, current));
            };
            current = self.safe_rekey_target_for_event(event_hash, &current)?;
        }
    }

    fn events_for_stable_fp_after(
        &self,
        stable_fp: &str,
        watermark: u64,
    ) -> Result<Vec<ProjectionEventRow>> {
        let mut stmt = self.conn.prepare(
            "select event_hash, event_kind from finding_events
              where stable_fp = ?1 and seq > ?2
              order by seq asc",
        )?;
        let rows = stmt.query_map(params![stable_fp, sql_watermark(watermark)?], |row| {
            Ok(ProjectionEventRow {
                event_hash: row.get(0)?,
                event_kind: row.get(1)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not load intervening finding event rows")
    }

    fn safe_rekey_target_for_event(&self, event_hash: &str, old_fp: &str) -> Result<String> {
        let edge = self
            .conn
            .query_row(
                "select new_fp, method, confidence from rekey_edges
                  where event_hash = ?1 and old_fp = ?2",
                params![event_hash, old_fp],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, f64>(2)?,
                    ))
                },
            )
            .optional()
            .context("Could not load rekey edge")?;
        let Some((new_fp, method, confidence)) = edge else {
            anyhow::bail!("rekey event {event_hash} has no projected edge");
        };
        if confidence >= 0.8 || method == "manual" {
            Ok(new_fp)
        } else {
            anyhow::bail!(
                "finding {old_fp} was rekeyed with low confidence {confidence:.3}; reload before deciding"
            );
        }
    }

    pub fn list_stable_findings(
        &self,
        options: ReadOptions,
    ) -> Result<ProjectionRead<Vec<StableFindingRead>>> {
        let meta = self.meta()?;
        require_read_watermark(meta, options)?;
        let mut stmt = self.conn.prepare(
            "select stable_fp, current_status, canonical_severity, canonical_title,
                    canonical_path, first_seen_seq, last_seen_seq, last_observation_hash
               from stable_findings
              order by last_seen_seq desc, stable_fp asc",
        )?;
        let rows = stmt
            .query_map([], stable_finding_read_row)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list v3 stable findings")?;
        Ok(ProjectionRead {
            applied_seq: meta.applied_seq,
            generation: meta.generation,
            rows,
        })
    }
}

fn require_read_watermark(meta: ProjectionMeta, options: ReadOptions) -> Result<()> {
    let Some(min_seq) = options.min_seq else {
        return Ok(());
    };
    if meta.applied_seq >= min_seq || options.staleness == StalenessPolicy::AllowStale {
        return Ok(());
    }
    anyhow::bail!(
        "projection watermark {} is behind required read seq {}",
        meta.applied_seq,
        min_seq
    )
}

fn stable_finding_read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StableFindingRead> {
    Ok(StableFindingRead {
        stable_fp: row.get(0)?,
        current_status: row.get(1)?,
        canonical_severity: row.get(2)?,
        canonical_title: row.get(3)?,
        canonical_path: row.get(4)?,
        first_seen_seq: sqlite_seq(row, 5)?,
        last_seen_seq: sqlite_seq(row, 6)?,
        last_observation_hash: row.get(7)?,
    })
}

fn configure_projection_connection(conn: &Connection) -> Result<()> {
    let _journal_mode: String =
        conn.query_row("pragma journal_mode = wal", [], |row| row.get(0))?;
    conn.busy_timeout(std::time::Duration::from_millis(5_000))?;
    conn.execute_batch("pragma foreign_keys = on;")?;
    Ok(())
}

pub(crate) fn create_projection_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(PROJECTION_SCHEMA)?;
    create_optional_fts(conn)?;
    Ok(())
}

fn meta_u64(conn: &Connection, key: &str) -> Result<u64> {
    conn.query_row("select value from meta where key = ?1", params![key], |row| {
        row.get::<_, String>(0)
    })?
    .parse::<u64>()
    .with_context(|| format!("projection meta key {key:?} is not an integer"))
}

fn set_meta_u64(conn: &Connection, key: &str, value: u64) -> Result<()> {
    conn.execute(
        "insert into meta(key, value) values (?1, ?2)
         on conflict(key) do update set value = excluded.value",
        params![key, value.to_string()],
    )?;
    Ok(())
}

fn sql_seq(seq: u64) -> Result<i64> {
    sql_u64(seq, "event seq")
}

fn sql_watermark(watermark: u64) -> Result<i64> {
    sql_u64(watermark, "read watermark")
}

fn sql_u64(value: u64, label: &str) -> Result<i64> {
    i64::try_from(value).with_context(|| format!("{label} exceeds SQLite INTEGER range: {value}"))
}

fn sqlite_seq(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value = row.get::<_, i64>(index)?;
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn create_optional_fts(conn: &Connection) -> Result<()> {
    match conn.execute_batch(FTS_SCHEMA) {
        Ok(()) => set_meta_u64(conn, "fts_available", 1),
        Err(_) => set_meta_u64(conn, "fts_available", 0),
    }
}

#[cfg(test)]
mod tests;
