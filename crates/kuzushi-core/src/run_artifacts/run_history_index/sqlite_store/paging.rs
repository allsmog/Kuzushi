use super::super::model::{IndexedRunHistoryPage, RunHistoryCursor, RunHistoryIndexEntry};
use anyhow::Result;
use rusqlite::Connection;
use std::fmt;
use std::path::Path;

#[derive(Debug)]
struct StaleRunHistoryCursor;

impl fmt::Display for StaleRunHistoryCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("run-history cursor belongs to an older index generation")
    }
}

impl std::error::Error for StaleRunHistoryCursor {}

pub(in crate::run_artifacts::run_history_index) fn is_stale_cursor_error(
    error: &anyhow::Error,
) -> bool {
    error.downcast_ref::<StaleRunHistoryCursor>().is_some()
}

pub(in crate::run_artifacts::run_history_index) fn read_index_window(
    target: &Path,
    offset: usize,
    limit: usize,
) -> Result<IndexedRunHistoryPage> {
    anyhow::ensure!(
        offset <= super::MAX_COMPATIBILITY_OFFSET,
        "run-history offset pagination is limited to {}; use a cursor",
        super::MAX_COMPATIBILITY_OFFSET
    );
    let (connection, metadata, retained_entries) = super::open_validated_index(target, false)?;
    let entries = super::entry_rows::read_offset(&connection, offset, limit)?;
    Ok(IndexedRunHistoryPage {
        entries,
        retained_entries,
        next_cursor: None,
        info: metadata.page_info(),
    })
}

pub(in crate::run_artifacts::run_history_index) fn read_index_after(
    target: &Path,
    cursor: Option<&RunHistoryCursor>,
    limit: usize,
) -> Result<IndexedRunHistoryPage> {
    let (connection, metadata, retained_entries) = super::open_validated_index(target, false)?;
    validate_cursor_generation(cursor, metadata.generation)?;
    let mut entries = read_cursor_rows(&connection, cursor, limit.saturating_add(1))?;
    let has_next = entries.len() > limit;
    entries.truncate(limit);
    let next_cursor = has_next
        .then(|| {
            entries
                .last()
                .map(|entry| entry.cursor(metadata.generation))
        })
        .flatten();
    Ok(IndexedRunHistoryPage {
        entries,
        retained_entries,
        next_cursor,
        info: metadata.page_info(),
    })
}

fn validate_cursor_generation(cursor: Option<&RunHistoryCursor>, generation: u64) -> Result<()> {
    let Some(cursor) = cursor else {
        return Ok(());
    };
    cursor.validate()?;
    if cursor.generation != generation {
        return Err(StaleRunHistoryCursor.into());
    }
    Ok(())
}

fn read_cursor_rows(
    connection: &Connection,
    cursor: Option<&RunHistoryCursor>,
    limit: usize,
) -> Result<Vec<RunHistoryIndexEntry>> {
    let Some(cursor) = cursor else {
        return super::entry_rows::read_offset(connection, 0, limit);
    };
    let (state, started, ready, issue) = cursor.sqlite_values()?;
    super::entry_rows::read_after(connection, state, started, ready, issue, limit)
}
