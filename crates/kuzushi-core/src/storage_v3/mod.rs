use crate::event_log::{EventEnvelope, EventKind};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};

mod projection_audit;
mod projection_event_store;
mod projection_finding_lifecycle;
mod projection_fts;
mod projection_observations;
mod projection_patch_lifecycle;
mod projection_payload;
mod projection_projectors;
mod projection_proof;
mod projection_rekey;
mod projection_review;
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

/// Events that record *looking at* a finding rather than changing it.
///
/// The decision staleness guard reads this list: a prospective review session
/// is an observation of the queue at the moment review began, so the session
/// the operator's own open recorded must not reject the verdict that open led
/// to. Every other event kind is a change a reviewer read against and so still
/// invalidates a stale decision.
const OBSERVATION_ONLY_EVENT_KINDS: &[EventKind] = &[EventKind::ReviewSessionStarted];

fn changes_finding_under_review(event_kind: &str) -> bool {
    !OBSERVATION_ONLY_EVENT_KINDS
        .iter()
        .any(|kind| kind.as_str() == event_kind)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionMeta {
    pub applied_seq: u64,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionApplyReceipt {
    pub review_decision_id: Option<i64>,
    pub finding_id: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StalenessPolicy {
    AllowStale,
    RejectStale,
    Wait {
        timeout: Duration,
        poll_interval: Duration,
    },
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

    pub fn wait_for_min_seq(min_seq: u64, timeout: Duration) -> Self {
        Self {
            min_seq: Some(min_seq),
            staleness: StalenessPolicy::Wait {
                timeout,
                poll_interval: Duration::from_millis(25),
            },
        }
    }

    pub fn wait_for_min_seq_with_poll(
        min_seq: u64,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Self {
        Self {
            min_seq: Some(min_seq),
            staleness: StalenessPolicy::Wait {
                timeout,
                poll_interval,
            },
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
        let conn = crate::sqlite_connection::open_file(path)?;
        configure_projection_connection(&conn)?;
        create_projection_schema(&conn)?;
        Ok(Self { conn })
    }

    #[cfg(test)]
    fn open_in_memory() -> Result<Self> {
        let conn =
            Connection::open_in_memory().context("Could not open in-memory v3 projection")?;
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

    fn apply_event(&self, event: &EventEnvelope) -> Result<ProjectionApplyReceipt> {
        let tx = self
            .conn
            .unchecked_transaction()
            .context("Could not open projection event transaction")?;
        let applied = meta_u64(&tx, "applied_seq")?;
        anyhow::ensure!(
            applied.checked_add(1) == Some(event.seq),
            "projection requires contiguous event sequence: applied {applied}, received {}",
            event.seq
        );
        insert_event_row(&tx, event)?;
        let receipt = apply_projection_event(&tx, event)?;
        set_meta_u64(&tx, "applied_seq", event.seq)?;
        tx.commit()
            .context("Could not commit projection event transaction")?;
        Ok(receipt)
    }

    fn rebuild_from_events(&self, events: &[EventEnvelope]) -> Result<u64> {
        let tx = self.conn.unchecked_transaction()?;
        let generation = meta_u64(&tx, "generation")?.saturating_add(1);
        clear_projection_tables(&tx)?;
        let mut applied = 0_u64;
        for event in events {
            anyhow::ensure!(
                applied.checked_add(1) == Some(event.seq),
                "rebuild event sequence has a gap"
            );
            insert_event_row(&tx, event)?;
            apply_projection_event(&tx, event)?;
            applied = event.seq;
        }
        set_meta_u64(&tx, "applied_seq", applied)?;
        set_meta_u64(&tx, "generation", generation)?;
        rebuild_fts_if_available(&tx)?;
        tx.commit()?;
        Ok(applied)
    }

    #[cfg(test)]
    fn reset_for_rebuild(&self) -> Result<ProjectionMeta> {
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
            "select seq, event_kind from finding_events
              where stable_fp = ?1 and seq > ?2
              order by seq asc",
        )?;
        let rows = stmt.query_map(params![stable_fp, sql_watermark(watermark)?], |row| {
            Ok((sqlite_seq(row, 0)?, row.get::<_, String>(1)?))
        })?;
        let rows = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not load intervening finding events")?;
        Ok(rows
            .into_iter()
            .filter(|(_, event_kind)| changes_finding_under_review(event_kind))
            .map(|(seq, _)| seq)
            .collect())
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
        let rows = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not load intervening finding event rows")?;
        Ok(rows
            .into_iter()
            .filter(|row| changes_finding_under_review(&row.event_kind))
            .collect())
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
        let meta = self.meta_for_read(options)?;
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

    fn meta_for_read(&self, options: ReadOptions) -> Result<ProjectionMeta> {
        let meta = self.meta()?;
        let Some(min_seq) = options.min_seq else {
            return Ok(meta);
        };
        if meta.applied_seq >= min_seq || options.staleness == StalenessPolicy::AllowStale {
            return Ok(meta);
        }
        match options.staleness {
            StalenessPolicy::AllowStale => Ok(meta),
            StalenessPolicy::RejectStale => reject_stale_projection(meta, min_seq),
            StalenessPolicy::Wait {
                timeout,
                poll_interval,
            } => self.wait_for_read_watermark(min_seq, timeout, poll_interval),
        }
    }

    fn wait_for_read_watermark(
        &self,
        min_seq: u64,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<ProjectionMeta> {
        let started = Instant::now();
        let poll_interval = nonzero_poll_interval(poll_interval);
        loop {
            let meta = self.meta()?;
            if meta.applied_seq >= min_seq {
                return Ok(meta);
            }
            sleep_before_next_watermark_poll(started, timeout, poll_interval, meta, min_seq)?;
        }
    }
}

pub(crate) fn projection_meta(conn: &Connection) -> Result<ProjectionMeta> {
    Ok(ProjectionMeta {
        applied_seq: meta_u64(conn, "applied_seq")?,
        generation: meta_u64(conn, "generation")?,
    })
}

fn reject_stale_projection<T>(meta: ProjectionMeta, min_seq: u64) -> Result<T> {
    anyhow::bail!(
        "projection watermark {} is behind required read seq {}",
        meta.applied_seq,
        min_seq
    )
}

fn sleep_before_next_watermark_poll(
    started: Instant,
    timeout: Duration,
    poll_interval: Duration,
    meta: ProjectionMeta,
    min_seq: u64,
) -> Result<()> {
    let elapsed = started.elapsed();
    if elapsed >= timeout {
        anyhow::bail!(
            "timed out waiting for projection watermark {} to reach required read seq {}",
            meta.applied_seq,
            min_seq
        );
    }
    std::thread::sleep(poll_interval.min(timeout - elapsed));
    Ok(())
}

fn nonzero_poll_interval(poll_interval: Duration) -> Duration {
    if poll_interval.is_zero() {
        Duration::from_millis(1)
    } else {
        poll_interval
    }
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
    let journal_mode: String = conn.query_row("pragma journal_mode", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") && journal_mode != "memory" {
        let _: String = conn.query_row("pragma journal_mode = wal", [], |row| row.get(0))?;
    }
    conn.busy_timeout(std::time::Duration::from_millis(5_000))?;
    conn.execute_batch("pragma foreign_keys = on;")?;
    Ok(())
}

pub(crate) fn create_projection_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(PROJECTION_SCHEMA)?;
    migrate_review_decision_dismissal_columns(conn)?;
    migrate_review_decision_provenance_columns(conn)?;
    migrate_review_decision_session_column(conn)?;
    migrate_review_decision_propagation_columns(conn)?;
    migrate_finding_identity_basis_column(conn)?;
    migrate_threat_model_version_ref_columns(conn)?;
    migrate_review_session_rank_objective_column(conn)?;
    migrate_verification_provenance_columns(conn)?;
    migrate_patch_cost_columns(conn)?;
    migrate_patch_lifecycle_columns(conn)?;
    create_optional_fts(conn)?;
    Ok(())
}

/// Additive and deliberately nullable: older projections only recorded the
/// broad match tier, so backfilling `stable_fp` as a high-confidence basis
/// would manufacture evidence. Readers derive those rows conservatively.
fn migrate_finding_identity_basis_column(conn: &Connection) -> Result<()> {
    if !table_has_column(conn, "finding_current", "identity_basis")? {
        conn.execute_batch("alter table finding_current add column identity_basis text")?;
    }
    if !table_has_column(conn, "finding_identity_fingerprints", "identity_basis")? {
        conn.execute_batch(
            "alter table finding_identity_fingerprints add column identity_basis text",
        )?;
    }
    Ok(())
}

/// Immutable model references did not exist in the original version ledger.
/// Both columns remain null on legacy rows rather than inferring a lineage
/// from document content or the compatibility mirror.
fn migrate_threat_model_version_ref_columns(conn: &Connection) -> Result<()> {
    for column in ["model_id", "revision_id"] {
        if !table_has_column(conn, "threat_model_versions", column)? {
            conn.execute_batch(&format!(
                "alter table threat_model_versions add column {column} text"
            ))?;
        }
    }
    conn.execute_batch(
        "create index if not exists idx_threat_model_versions_ref
           on threat_model_versions(model_id, revision_id, id desc)",
    )?;
    Ok(())
}

fn migrate_patch_lifecycle_columns(conn: &Connection) -> Result<()> {
    for table in ["patch_lifecycle_events", "patch_lifecycle_current"] {
        if !table_has_column(conn, table, "finding_scan_id")? {
            conn.execute_batch(&format!(
                "alter table {table} add column finding_scan_id text"
            ))?;
        }
        if !table_has_column(conn, table, "application_started_at")? {
            conn.execute_batch(&format!(
                "alter table {table} add column application_started_at text"
            ))?;
        }
        if !table_has_column(conn, table, "reverify_evidence_json")? {
            conn.execute_batch(&format!(
                "alter table {table} add column reverify_evidence_json text"
            ))?;
        }
        conn.execute(
            &format!(
                "update {table} set application_started_at = applied_at \
                 where application_started_at is null or application_started_at = ''"
            ),
            [],
        )?;
    }
    Ok(())
}

fn migrate_patch_cost_columns(conn: &Connection) -> Result<()> {
    if !table_has_column(conn, "patch_attempt_events", "provider_spend_unresolved")? {
        conn.execute_batch(
            "alter table patch_attempt_events add column provider_spend_unresolved integer",
        )?;
    }
    Ok(())
}

fn migrate_verification_provenance_columns(conn: &Connection) -> Result<()> {
    for column in ["verification_run_id", "verified_scan_id", "provenance_json"] {
        if !table_has_column(conn, "verification_events", column)? {
            conn.execute_batch(&format!(
                "alter table verification_events add column {column} text"
            ))?;
        }
    }
    Ok(())
}

/// Idempotent, additive migration for pre-existing projection DBs that were
/// created before the dismissal columns landed. `create table if not exists`
/// leaves older tables untouched, so add the columns when they are absent.
fn migrate_review_decision_dismissal_columns(conn: &Connection) -> Result<()> {
    for column in ["dismiss_reason", "dismissed_by"] {
        if !review_decisions_has_column(conn, column)? {
            conn.execute_batch(&format!(
                "alter table review_decisions add column {column} text"
            ))?;
        }
    }
    Ok(())
}

fn review_decisions_has_column(conn: &Connection, column: &str) -> Result<bool> {
    table_has_column(conn, "review_decisions", column)
}

/// Idempotent, additive migration linking a decision to the prospective review
/// session it concluded. Deliberately unbackfilled: decisions taken before
/// sessions existed genuinely have none, and inventing one would fabricate the
/// very measurement this column exists to make.
fn migrate_review_decision_session_column(conn: &Connection) -> Result<()> {
    if !review_decisions_has_column(conn, "review_session_id")? {
        conn.execute_batch("alter table review_decisions add column review_session_id text")?;
    }
    Ok(())
}

/// Additive audit provenance for basis-aware automatic propagation. Existing
/// decision events genuinely carry no such proof, so both columns stay null.
fn migrate_review_decision_propagation_columns(conn: &Connection) -> Result<()> {
    for column in ["propagation_basis", "source_finding_ids_json"] {
        if !review_decisions_has_column(conn, column)? {
            conn.execute_batch(&format!(
                "alter table review_decisions add column {column} text"
            ))?;
        }
    }
    Ok(())
}

/// Idempotent, additive migration naming what objective a session's
/// `shadow_rank` ranks by. Deliberately unbackfilled: rows written before the
/// column existed carry a yield ranking, but stamping that on them after the
/// fact would assert a provenance the record never had. A null objective reads
/// as "this row does not say".
fn migrate_review_session_rank_objective_column(conn: &Connection) -> Result<()> {
    if !table_has_column(conn, "review_sessions", "shadow_rank_objective")? {
        conn.execute_batch("alter table review_sessions add column shadow_rank_objective text")?;
    }
    Ok(())
}

/// Idempotent, additive migration that retains each decision's exact event
/// provenance (`seq`, `event_hash`, payload `readWatermark`). Pre-existing
/// rows are backfilled once from `finding_events`, where the full decision
/// payload already survives; rows whose event cannot be recovered keep null
/// provenance instead of a fabricated one.
fn migrate_review_decision_provenance_columns(conn: &Connection) -> Result<()> {
    let mut added = false;
    for (column, kind) in [
        ("decision_event_seq", "integer"),
        ("decision_event_hash", "text"),
        ("decision_read_watermark", "integer"),
    ] {
        if !review_decisions_has_column(conn, column)? {
            conn.execute_batch(&format!(
                "alter table review_decisions add column {column} {kind}"
            ))?;
            added = true;
        }
    }
    if added {
        backfill_review_decision_provenance(conn)?;
    }
    // Created here rather than in PROJECTION_SCHEMA because on a legacy DB
    // these columns only exist after the alters above.
    conn.execute_batch(
        r#"
        create unique index if not exists idx_review_decisions_event_hash
          on review_decisions(decision_event_hash)
          where decision_event_hash is not null;
        create index if not exists idx_review_decisions_finding_seq
          on review_decisions(finding_id, decision_event_seq);
        create index if not exists idx_review_decisions_identity_seq
          on review_decisions(identity_id, decision_event_seq)
          where identity_id is not null;
        "#,
    )?;
    Ok(())
}

/// One-shot backfill run when the provenance columns are first added. The
/// projector inserts one `review_decisions` row per qualifying decision event
/// in event order, so rank-matching by position recovers the pairing; the
/// join additionally requires the finding id and timestamp to agree so a
/// diverged event store leaves nulls rather than misattributed provenance.
fn backfill_review_decision_provenance(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        update review_decisions
           set decision_event_seq = matched.seq,
               decision_event_hash = matched.event_hash,
               decision_read_watermark = matched.read_watermark
          from (
            select ranked_decisions.id as decision_id,
                   ranked_events.seq,
                   ranked_events.event_hash,
                   ranked_events.read_watermark
              from (
                select id, finding_id, created_at,
                       row_number() over (order by id asc) as rn
                  from review_decisions
              ) as ranked_decisions
              join (
                select seq, event_hash, created_at,
                       json_extract(payload_json, '$.findingId') as finding_id,
                       json_extract(payload_json, '$.readWatermark') as read_watermark,
                       row_number() over (order by seq asc) as rn
                  from finding_events
                 where event_kind in ('triage-decided', 'suppression-added')
                   and json_type(payload_json, '$.findingId') = 'integer'
              ) as ranked_events
                on ranked_events.rn = ranked_decisions.rn
               and ranked_events.finding_id = ranked_decisions.finding_id
               and ranked_events.created_at = ranked_decisions.created_at
          ) as matched
         where review_decisions.id = matched.decision_id
        "#,
    )?;
    Ok(())
}

fn table_has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("pragma table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn meta_u64(conn: &Connection, key: &str) -> Result<u64> {
    conn.query_row(
        "select value from meta where key = ?1",
        params![key],
        |row| row.get::<_, String>(0),
    )?
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
