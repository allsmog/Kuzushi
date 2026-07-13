use super::{DirectoryStamp, IndexMetadata};
use crate::run_artifacts::run_history_index::model::RunHistoryCursor;
use crate::run_artifacts::run_history_index::retention::RetentionPolicy;
use anyhow::{Context, Result};
use rusqlite::{params, Connection, Transaction};

pub(super) fn load(connection: &Connection) -> Result<IndexMetadata> {
    connection
        .query_row(METADATA_SELECT, [], metadata_from_row)
        .context("run-history metadata row is missing")
}

pub(super) fn write(metadata: &IndexMetadata, transaction: &Transaction<'_>) -> Result<()> {
    metadata.validate_fields()?;
    let oldest = metadata.oldest_sql_values()?;
    transaction.execute(
        METADATA_UPSERT,
        params![
            super::super::schema::INDEX_SCHEMA_VERSION,
            i64::from(metadata.stamp.present),
            metadata.stamp.secs,
            metadata.stamp.nanos,
            checked_i64(metadata.canonical_total, "canonical total")?,
            checked_i64(metadata.retained_count, "retained count")?,
            checked_i64(metadata.retained_bytes, "retained bytes")?,
            i64::try_from(metadata.policy.max_rows)
                .context("run-history row policy does not fit SQLite")?,
            checked_i64(metadata.policy.max_bytes, "byte policy")?,
            oldest.0,
            oldest.1,
            oldest.2,
            oldest.3,
            i64::from(metadata.truncated),
            checked_i64(metadata.generation, "generation")?,
            metadata.canonical_xor.as_slice(),
            metadata.canonical_digest,
            metadata.table_digest,
        ],
    )?;
    Ok(())
}

const METADATA_SELECT: &str = "SELECT runs_present, runs_secs, runs_nanos,
       canonical_total, retained_count, retained_bytes,
       retention_max_rows, retention_max_bytes,
       oldest_state_rank, oldest_started_at_unix,
       oldest_ready_run_id, oldest_issue_run_id,
       truncated, generation, canonical_xor, canonical_digest, table_digest
  FROM run_history_meta WHERE singleton = 1";

const METADATA_UPSERT: &str = "INSERT INTO run_history_meta (
       singleton, schema_version, runs_present, runs_secs, runs_nanos,
       canonical_total, retained_count, retained_bytes,
       retention_max_rows, retention_max_bytes,
       oldest_state_rank, oldest_started_at_unix,
       oldest_ready_run_id, oldest_issue_run_id,
       truncated, generation, canonical_xor, canonical_digest, table_digest
     ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
               ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
     ON CONFLICT(singleton) DO UPDATE SET
       schema_version=excluded.schema_version,
       runs_present=excluded.runs_present, runs_secs=excluded.runs_secs,
       runs_nanos=excluded.runs_nanos, canonical_total=excluded.canonical_total,
       retained_count=excluded.retained_count, retained_bytes=excluded.retained_bytes,
       retention_max_rows=excluded.retention_max_rows,
       retention_max_bytes=excluded.retention_max_bytes,
       oldest_state_rank=excluded.oldest_state_rank,
       oldest_started_at_unix=excluded.oldest_started_at_unix,
       oldest_ready_run_id=excluded.oldest_ready_run_id,
       oldest_issue_run_id=excluded.oldest_issue_run_id,
       truncated=excluded.truncated, generation=excluded.generation,
       canonical_xor=excluded.canonical_xor,
       canonical_digest=excluded.canonical_digest,
       table_digest=excluded.table_digest";

fn metadata_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<IndexMetadata> {
    let xor: Vec<u8> = row.get(14)?;
    let canonical_xor: [u8; 32] = xor.try_into().map_err(|_| invalid_metadata_error())?;
    let oldest_retained = cursor_from_row(row)?;
    Ok(IndexMetadata {
        stamp: DirectoryStamp {
            present: checked_bool(row.get(0)?)?,
            secs: row.get(1)?,
            nanos: row.get(2)?,
        },
        canonical_total: checked_u64(row.get(3)?)?,
        retained_count: checked_u64(row.get(4)?)?,
        retained_bytes: checked_u64(row.get(5)?)?,
        policy: RetentionPolicy {
            max_rows: checked_usize(row.get(6)?)?,
            max_bytes: checked_u64(row.get(7)?)?,
        },
        oldest_retained,
        truncated: checked_bool(row.get(12)?)?,
        generation: checked_u64(row.get(13)?)?,
        canonical_xor,
        canonical_digest: row.get(15)?,
        table_digest: row.get(16)?,
    })
}

fn cursor_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Option<RunHistoryCursor>> {
    let state: Option<i64> = row.get(8)?;
    let started: Option<i64> = row.get(9)?;
    let ready: Option<String> = row.get(10)?;
    let issue: Option<String> = row.get(11)?;
    let Some(state) = state else {
        if started.is_some() || ready.is_some() || issue.is_some() {
            return Err(invalid_metadata_error());
        }
        return Ok(None);
    };
    Ok(Some(RunHistoryCursor {
        generation: checked_u64(row.get(13)?)?,
        state_rank: u8::try_from(state).map_err(|_| invalid_metadata_error())?,
        started_at_unix: checked_u64(started.ok_or_else(invalid_metadata_error)?)?,
        ready_run_id: ready.ok_or_else(invalid_metadata_error)?,
        issue_run_id: issue.ok_or_else(invalid_metadata_error)?,
    }))
}

fn checked_i64(value: u64, label: &str) -> Result<i64> {
    i64::try_from(value).with_context(|| format!("run-history {label} does not fit SQLite"))
}

fn checked_u64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| invalid_metadata_error())
}

fn checked_usize(value: i64) -> rusqlite::Result<usize> {
    usize::try_from(value).map_err(|_| invalid_metadata_error())
}

fn checked_bool(value: i64) -> rusqlite::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid_metadata_error()),
    }
}

fn invalid_metadata_error() -> rusqlite::Error {
    rusqlite::Error::InvalidQuery
}
