use super::super::super::RunSummaryIssue;
use super::super::model::{RunHistoryIndexEntry, ISSUE_STATE, MAX_ISSUE_JSON_BYTES, READY_STATE};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, Transaction};

const ENTRY_SELECT: &str = "SELECT run_id, state_rank, started_at_unix,
       ready_run_id, issue_run_id,
       CASE WHEN issue_json IS NULL OR length(issue_json) <= ?1
            THEN issue_json ELSE NULL END,
       entry_bytes
  FROM run_history_entries";

pub(super) fn load_all_bounded(
    connection: &Connection,
    max_rows: usize,
) -> Result<Vec<RunHistoryIndexEntry>> {
    let sql = format!(
        "{ENTRY_SELECT}
         ORDER BY state_rank ASC, started_at_unix DESC,
                  ready_run_id DESC, issue_run_id ASC
         LIMIT ?2"
    );
    let mut statement = connection.prepare_cached(&sql)?;
    let limit = sqlite_limit(max_rows.saturating_add(1))?;
    let rows = statement.query_map(params![max_issue_bytes(), limit], row_to_entry)?;
    let entries = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    anyhow::ensure!(
        entries.len() <= max_rows,
        "run-history index exceeds its retained row policy"
    );
    entries.into_iter().map(validate_stored_entry).collect()
}

pub(super) fn read_offset(
    connection: &Connection,
    offset: usize,
    limit: usize,
) -> Result<Vec<RunHistoryIndexEntry>> {
    let sql = format!(
        "{ENTRY_SELECT}
         ORDER BY state_rank ASC, started_at_unix DESC,
                  ready_run_id DESC, issue_run_id ASC
         LIMIT ?2 OFFSET ?3"
    );
    let mut statement = connection.prepare_cached(&sql)?;
    let rows = statement.query_map(
        params![
            max_issue_bytes(),
            sqlite_limit(limit)?,
            sqlite_limit(offset)?
        ],
        row_to_entry,
    )?;
    rows.collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .map(validate_stored_entry)
        .collect()
}

pub(super) fn read_after(
    connection: &Connection,
    state_rank: i64,
    started_at: i64,
    ready_run_id: &str,
    issue_run_id: &str,
    limit: usize,
) -> Result<Vec<RunHistoryIndexEntry>> {
    let sql = format!(
        "{ENTRY_SELECT}
         WHERE state_rank > ?2
            OR (state_rank = ?2 AND started_at_unix < ?3)
            OR (state_rank = ?2 AND started_at_unix = ?3 AND ready_run_id < ?4)
            OR (state_rank = ?2 AND started_at_unix = ?3 AND ready_run_id = ?4
                AND issue_run_id > ?5)
         ORDER BY state_rank ASC, started_at_unix DESC,
                  ready_run_id DESC, issue_run_id ASC
         LIMIT ?6"
    );
    let mut statement = connection.prepare_cached(&sql)?;
    let rows = statement.query_map(
        params![
            max_issue_bytes(),
            state_rank,
            started_at,
            ready_run_id,
            issue_run_id,
            sqlite_limit(limit)?
        ],
        row_to_entry,
    )?;
    rows.collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .map(validate_stored_entry)
        .collect()
}

pub(super) fn replace_all(
    transaction: &Transaction<'_>,
    entries: &[RunHistoryIndexEntry],
) -> Result<()> {
    transaction.execute("DELETE FROM run_history_entries", [])?;
    for entry in entries {
        upsert(transaction, entry)?;
    }
    Ok(())
}

fn upsert(transaction: &Transaction<'_>, entry: &RunHistoryIndexEntry) -> Result<()> {
    entry.validate()?;
    let values = sqlite_entry_values(entry)?;
    transaction.execute(
        "INSERT INTO run_history_entries
         (run_id, state_rank, started_at_unix, ready_run_id,
          issue_run_id, issue_json, entry_bytes)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            entry.run_id,
            values.state,
            values.started,
            values.ready_id,
            values.issue_id,
            values.issue_json,
            i64::try_from(entry.retained_bytes()?)
                .context("run-history entry byte count does not fit SQLite")?
        ],
    )?;
    Ok(())
}

struct SqliteEntryValues {
    state: i64,
    started: i64,
    ready_id: String,
    issue_id: String,
    issue_json: Option<String>,
}

fn sqlite_entry_values(entry: &RunHistoryIndexEntry) -> Result<SqliteEntryValues> {
    match (&entry.started_at_unix, &entry.issue) {
        (Some(started), None) => Ok(SqliteEntryValues {
            state: READY_STATE,
            started: i64::try_from(*started).context("run start time does not fit SQLite")?,
            ready_id: entry.run_id.clone(),
            issue_id: String::new(),
            issue_json: None,
        }),
        (None, Some(issue)) => Ok(SqliteEntryValues {
            state: ISSUE_STATE,
            started: 0,
            ready_id: String::new(),
            issue_id: entry.run_id.clone(),
            issue_json: Some(bounded_issue_json(issue)?),
        }),
        _ => anyhow::bail!("run-history index entry state is invalid"),
    }
}

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEntry> {
    Ok(StoredEntry {
        run_id: row.get(0)?,
        state: row.get(1)?,
        started: row.get(2)?,
        ready_id: row.get(3)?,
        issue_id: row.get(4)?,
        issue_json: row.get(5)?,
        stored_bytes: row.get(6)?,
    })
}

struct StoredEntry {
    run_id: String,
    state: i64,
    started: i64,
    ready_id: String,
    issue_id: String,
    issue_json: Option<String>,
    stored_bytes: i64,
}

fn validate_stored_entry(stored: StoredEntry) -> Result<RunHistoryIndexEntry> {
    let entry = match stored.state {
        READY_STATE => ready_entry(&stored)?,
        ISSUE_STATE => issue_entry(&stored)?,
        _ => anyhow::bail!("run-history index state rank is invalid"),
    };
    entry.validate()?;
    anyhow::ensure!(
        stored.stored_bytes >= 0
            && u64::try_from(stored.stored_bytes).ok() == Some(entry.retained_bytes()?),
        "run-history entry byte metadata is invalid"
    );
    Ok(entry)
}

fn ready_entry(stored: &StoredEntry) -> Result<RunHistoryIndexEntry> {
    anyhow::ensure!(
        stored.ready_id == stored.run_id
            && stored.issue_id.is_empty()
            && stored.issue_json.is_none(),
        "run-history ready ordering key is invalid"
    );
    Ok(RunHistoryIndexEntry {
        run_id: stored.run_id.clone(),
        started_at_unix: Some(
            u64::try_from(stored.started).context("run-history ready timestamp is invalid")?,
        ),
        issue: None,
    })
}

fn issue_entry(stored: &StoredEntry) -> Result<RunHistoryIndexEntry> {
    anyhow::ensure!(
        stored.started == 0 && stored.ready_id.is_empty() && stored.issue_id == stored.run_id,
        "run-history issue ordering key is invalid"
    );
    let encoded = stored
        .issue_json
        .as_deref()
        .context("run-history issue payload is missing or oversized")?;
    Ok(RunHistoryIndexEntry {
        run_id: stored.run_id.clone(),
        started_at_unix: None,
        issue: Some(serde_json::from_str(encoded).context("run-history issue JSON is invalid")?),
    })
}

fn bounded_issue_json(issue: &RunSummaryIssue) -> Result<String> {
    let encoded = serde_json::to_string(issue)?;
    anyhow::ensure!(
        encoded.len() <= MAX_ISSUE_JSON_BYTES,
        "run-history issue exceeds the index limit"
    );
    Ok(encoded)
}

fn max_issue_bytes() -> i64 {
    i64::try_from(MAX_ISSUE_JSON_BYTES).unwrap_or(i64::MAX)
}

fn sqlite_limit(value: usize) -> Result<i64> {
    i64::try_from(value).context("run-history page value does not fit SQLite")
}
