use std::collections::BTreeMap;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};

use super::rows::{decision_row, observation_row, DecisionRow, ObservationMeta};
use crate::findings::FindingStore;
use crate::storage_v3::ProjectionMeta;
use crate::workspace::WorkspaceTarget;

const DECISION_QUERY: &str = "\
select identity_id, decision_verdict, author, dismiss_reason,
       decision_event_seq, decision_event_hash, decision_read_watermark
  from review_decisions
 order by (decision_event_seq is null), decision_event_seq asc, created_at asc, id asc";

const OBSERVATION_QUERY: &str = "\
select coalesce(nullif(json_extract(finding_json, '$.identityId'), ''), '') as identity_id,
       observation_hash, snapshot_hash, created_seq, run_id, tool
  from finding_observations
 where finding_json is not null
   and coalesce(nullif(json_extract(finding_json, '$.identityId'), ''), '') != ''
 order by created_seq asc";

const REOPENED_QUERY: &str = "\
select count(*)
  from finding_events as event
  join finding_identity_fingerprints as fingerprint
    on event.stable_fp = fingerprint.fingerprint
 where fingerprint.identity_id = ?1
   and event.event_kind = 'finding-reopened'
   and event.seq <= ?2";

/// Every stored snapshot in identity then sequence order, so the caller can
/// keep the last row per identity without a per-identity query.
const HEAD_SNAPSHOT_QUERY: &str = "\
select coalesce(nullif(json_extract(finding_json, '$.identityId'), ''), '') as identity_id,
       finding_json
  from finding_observations
 where finding_json is not null
   and coalesce(nullif(json_extract(finding_json, '$.identityId'), ''), '') != ''
 order by identity_id asc, created_seq asc";

const REOPENED_TOTALS_QUERY: &str = "\
select fingerprint.identity_id, count(*)
  from finding_events as event
  join finding_identity_fingerprints as fingerprint
    on event.stable_fp = fingerprint.fingerprint
 where event.event_kind = 'finding-reopened'
 group by fingerprint.identity_id";

/// Read-only view of the findings projection, scoped to exactly the tables the
/// review-yield export is allowed to touch.
pub struct ReviewYieldProjectionReader {
    conn: Connection,
}

impl ReviewYieldProjectionReader {
    /// Fails when the target has no recorded findings database; never creates
    /// one. Opens the store read-write once first so the decision-provenance
    /// migration and backfill have run, then reads through a read-only handle.
    pub fn open(workspace: &WorkspaceTarget) -> Result<Self> {
        let db_path = workspace.findings_db_path();
        anyhow::ensure!(
            db_path.exists(),
            "No recorded findings database at {}. Next: run a scan against this target first.",
            db_path.display()
        );
        FindingStore::open(&db_path)
            .context("could not open the findings projection for review-yield")?;
        let conn = crate::sqlite_connection::open_read_only_file(&db_path)
            .context("could not open the findings projection read-only")?;
        Ok(Self { conn })
    }

    /// Every recorded review decision, in event order. Rows without event
    /// provenance sort last and are counted, never dropped.
    pub fn all_decisions(&self) -> Result<Vec<DecisionRow>> {
        let mut statement = self.conn.prepare(DECISION_QUERY)?;
        let rows = statement
            .query_map([], decision_row)?
            .collect::<rusqlite::Result<Vec<DecisionRow>>>()
            .context("could not read recorded review decisions")?;
        Ok(rows)
    }

    /// Pre-cutoff snapshot metadata for every durable identity, ascending by
    /// event sequence. Observations without a durable identity are skipped:
    /// they cannot be joined to a decision.
    pub fn observation_index(&self) -> Result<BTreeMap<String, Vec<ObservationMeta>>> {
        let mut statement = self.conn.prepare(OBSERVATION_QUERY)?;
        let mut index: BTreeMap<String, Vec<ObservationMeta>> = BTreeMap::new();
        for row in statement.query_map([], observation_row)? {
            let (identity_id, meta) = row.context("could not read a finding observation")?;
            index.entry(identity_id).or_default().push(meta);
        }
        Ok(index)
    }

    /// The stored finding snapshot for one observation. Only the anchor
    /// observation of an exported row is ever fetched.
    pub fn observation_json(&self, observation_hash: &str) -> Result<String> {
        self.conn
            .query_row(
                "select finding_json from finding_observations where observation_hash = ?1",
                [observation_hash],
                |row| row.get::<_, Option<String>>(0),
            )
            .context("could not read the anchor observation snapshot")?
            .with_context(|| format!("observation {observation_hash} has no stored snapshot"))
    }

    /// The newest stored snapshot of every durable identity, in one query.
    /// Runtime scoring reads the whole set once instead of per finding.
    pub fn head_snapshots(&self) -> Result<BTreeMap<String, String>> {
        let mut statement = self.conn.prepare(HEAD_SNAPSHOT_QUERY)?;
        let mut heads: BTreeMap<String, String> = BTreeMap::new();
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (identity_id, finding_json) = row.context("could not read a finding snapshot")?;
            heads.insert(identity_id, finding_json);
        }
        Ok(heads)
    }

    /// Reopen counts for every identity, in one query. Identities with no
    /// reopen event are absent rather than zero-valued rows.
    pub fn reopened_counts(&self) -> Result<BTreeMap<String, u32>> {
        let mut statement = self.conn.prepare(REOPENED_TOTALS_QUERY)?;
        let mut counts: BTreeMap<String, u32> = BTreeMap::new();
        let rows = statement
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?;
        for row in rows {
            let (identity_id, count) = row.context("could not read a reopen count")?;
            counts.insert(identity_id, u32::try_from(count).unwrap_or(u32::MAX));
        }
        Ok(counts)
    }

    pub fn reopened_count_before(&self, identity_id: &str, cutoff: u64) -> Result<u32> {
        let count: i64 = self.conn.query_row(
            REOPENED_QUERY,
            rusqlite::params![identity_id, i64::try_from(cutoff)?],
            |row| row.get(0),
        )?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    /// `None` means no target snapshot has been recorded yet, which the caller
    /// may legitimately fall back from. A failed read is an error, not an empty
    /// result: silently recomputing the fingerprint would mask a broken
    /// projection.
    pub fn latest_workspace_root_fingerprint(&self) -> Result<Option<String>> {
        self.conn
            .query_row(
                "select workspace_root_fingerprint from target_snapshots
                  order by created_at desc, rowid desc limit 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .context("could not read the latest recorded target snapshot")
    }

    pub fn distinct_repository_count(&self) -> Result<u64> {
        let count: i64 = self.conn.query_row(
            "select count(distinct workspace_root_fingerprint) from target_snapshots",
            [],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(count).unwrap_or_default())
    }

    pub fn projection_meta(&self) -> Result<ProjectionMeta> {
        crate::storage_v3::projection_meta(&self.conn)
    }
}
