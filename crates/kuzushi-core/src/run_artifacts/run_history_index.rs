//! Rebuildable, bounded row index for run-history pages.

mod model;
mod retention;
mod sqlite_store;

pub(super) use model::{CurrentRunHistoryPrefix, IndexedRunHistoryPage, RunHistoryIndexEntry};
pub use model::{RunHistoryCursor, RunHistoryPageInfo};

use super::{checked_run_history_dirty_path, RunSummary};
use anyhow::{Context, Result};
use retention::{RetentionBuilder, RetentionPolicy};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SummaryIndexTransition {
    Existing,
    MissingMetadata,
    Rebuild,
}

pub(super) fn mark_run_history_dirty(
    target: &Path,
    _guard: &crate::file_lock::ExclusiveFileLock,
) -> Result<()> {
    mark_run_history_dirty_best_effort(target)
}

pub(super) fn prepare_run_history_update_under_lock(
    target: &Path,
    guard: &crate::file_lock::ExclusiveFileLock,
) -> Result<()> {
    if !current_index_is_available(target) {
        rebuild_index_and_clear_dirty(target, guard)?;
    }
    mark_run_history_dirty(target, guard)
}

pub(super) fn mark_run_history_dirty_best_effort(target: &Path) -> Result<()> {
    let path = checked_run_history_dirty_path(target)?;
    crate::fs_atomic::write_atomic(&path, "dirty\n")
        .with_context(|| format!("Could not mark run-history index dirty: {}", path.display()))
}

pub(super) fn clear_run_history_dirty(
    target: &Path,
    _guard: &crate::file_lock::ExclusiveFileLock,
) -> Result<()> {
    let path = checked_run_history_dirty_path(target)?;
    match fs::remove_file(&path) {
        Ok(()) => crate::fs_atomic::sync_parent_dir(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
    .with_context(|| {
        format!(
            "Could not clear run-history dirty marker {}",
            path.display()
        )
    })
}

pub(super) fn update_run_history_index_under_lock(
    target: &Path,
    summary: &RunSummary,
    transition: SummaryIndexTransition,
    _guard: &crate::file_lock::ExclusiveFileLock,
) -> Result<()> {
    if transition == SummaryIndexTransition::Rebuild {
        return rebuild_index(target, current_retention_policy(target));
    }
    let previous_was_missing = transition == SummaryIndexTransition::MissingMetadata;
    if sqlite_store::upsert_summary(target, summary, previous_was_missing).is_ok() {
        return Ok(());
    }
    rebuild_index(target, current_retention_policy(target))
}

pub(super) fn record_run_directory_best_effort(
    target: &Path,
    run_id: &str,
    guard: Option<&crate::file_lock::ExclusiveFileLock>,
) {
    let Some(guard) = guard else {
        let _ = mark_run_history_dirty_best_effort(target);
        return;
    };
    if sqlite_store::upsert_missing_run(target, run_id).is_ok()
        && clear_run_history_dirty(target, guard).is_err()
    {
        let _ = mark_run_history_dirty_best_effort(target);
    }
}

pub(super) fn load_run_history_page(
    target: &Path,
    offset: usize,
    limit: usize,
) -> Result<IndexedRunHistoryPage> {
    validate_page_window(offset, limit)?;
    if limit == 0 {
        return empty_page(target);
    }
    ensure_current_index(target)?;
    match sqlite_store::read_index_window(target, offset, limit) {
        Ok(page) => Ok(page),
        Err(_) => rebuild_then_read_window(target, offset, limit),
    }
}

pub(super) fn load_current_run_history_prefix(
    target: &Path,
    limit: usize,
) -> Result<Option<CurrentRunHistoryPrefix>> {
    validate_cursor_window(limit)?;
    if dirty_marker_state(target)? != DirtyMarkerState::Clean {
        return Ok(None);
    }
    let prefix = match sqlite_store::read_current_prefix(target, limit) {
        Ok(prefix) => prefix,
        Err(_) => return Ok(None),
    };
    if dirty_marker_state(target)? != DirtyMarkerState::Clean {
        return Ok(None);
    }
    Ok(Some(prefix))
}

pub(super) fn load_run_history_cursor_page(
    target: &Path,
    cursor: Option<&RunHistoryCursor>,
    limit: usize,
) -> Result<IndexedRunHistoryPage> {
    validate_cursor_window(limit)?;
    ensure_current_index(target)?;
    if limit == 0 {
        return sqlite_store::read_index_after(target, cursor, 0);
    }
    match sqlite_store::read_index_after(target, cursor, limit) {
        Ok(page) => Ok(page),
        Err(error) if sqlite_store::is_stale_cursor_error(&error) => Err(error),
        Err(_) => rebuild_then_read_cursor(target, cursor, limit),
    }
}

pub(super) fn rebuild_then_load_page(
    target: &Path,
    offset: usize,
    limit: usize,
) -> Result<IndexedRunHistoryPage> {
    validate_page_window(offset, limit)?;
    rebuild_then_read_window(target, offset, limit)
}

pub(super) fn rebuild_then_load_cursor_page(
    target: &Path,
    cursor: Option<&RunHistoryCursor>,
    limit: usize,
) -> Result<IndexedRunHistoryPage> {
    validate_cursor_window(limit)?;
    rebuild_then_read_cursor(target, cursor, limit)
}

fn validate_page_window(offset: usize, limit: usize) -> Result<()> {
    validate_cursor_window(limit)?;
    anyhow::ensure!(
        offset <= sqlite_store::MAX_COMPATIBILITY_OFFSET,
        "run-history offset pagination is limited to {}; use a cursor",
        sqlite_store::MAX_COMPATIBILITY_OFFSET
    );
    Ok(())
}

fn validate_cursor_window(limit: usize) -> Result<()> {
    anyhow::ensure!(
        limit <= sqlite_store::MAX_PAGE_WINDOW,
        "run-history page limit exceeds {}",
        sqlite_store::MAX_PAGE_WINDOW
    );
    Ok(())
}

fn ensure_current_index(target: &Path) -> Result<()> {
    if current_index_is_available(target) {
        return Ok(());
    }
    let guard = super::run_ledger::acquire_run_history_index_lock(target)?;
    if current_index_is_available(target) {
        return Ok(());
    }
    rebuild_index_and_clear_dirty(target, &guard)
}

fn current_index_is_available(target: &Path) -> bool {
    matches!(dirty_marker_state(target), Ok(DirtyMarkerState::Clean))
        && sqlite_store::validate_current_index(target).is_ok()
}

pub(super) fn page_generation_is_current(target: &Path, expected: u64) -> bool {
    matches!(dirty_marker_state(target), Ok(DirtyMarkerState::Clean))
        && sqlite_store::current_generation(target).is_ok_and(|current| current == expected)
}

fn empty_page(target: &Path) -> Result<IndexedRunHistoryPage> {
    ensure_current_index(target)?;
    sqlite_store::read_index_window(target, 0, 0)
}

fn rebuild_then_read_window(
    target: &Path,
    offset: usize,
    limit: usize,
) -> Result<IndexedRunHistoryPage> {
    let guard = super::run_ledger::acquire_run_history_index_lock(target)?;
    rebuild_index_and_clear_dirty(target, &guard)?;
    sqlite_store::read_index_window(target, offset, limit)
}

fn rebuild_then_read_cursor(
    target: &Path,
    cursor: Option<&RunHistoryCursor>,
    limit: usize,
) -> Result<IndexedRunHistoryPage> {
    let guard = super::run_ledger::acquire_run_history_index_lock(target)?;
    rebuild_index_and_clear_dirty(target, &guard)?;
    sqlite_store::read_index_after(target, cursor, limit)
}

fn rebuild_index_and_clear_dirty(
    target: &Path,
    guard: &crate::file_lock::ExclusiveFileLock,
) -> Result<()> {
    quarantine_invalid_dirty_marker(target)?;
    rebuild_index(target, current_retention_policy(target))?;
    clear_run_history_dirty(target, guard)
}

fn rebuild_index(target: &Path, policy: RetentionPolicy) -> Result<()> {
    let generation = fresh_generation();
    let before = sqlite_store::capture_directory_stamp(target)?;
    let retained = rebuild_entries(target, policy)?;
    let after = sqlite_store::capture_directory_stamp(target)?;
    anyhow::ensure!(
        before == after,
        "run-history directory changed during index rebuild"
    );
    sqlite_store::replace_index(target, &retained, policy, generation, after)?;
    sqlite_store::remove_legacy_index_after_rebuild(target)
}

fn current_retention_policy(target: &Path) -> RetentionPolicy {
    sqlite_store::stored_retention_policy(target).unwrap_or_default()
}

fn fresh_generation() -> u64 {
    loop {
        let bytes = uuid::Uuid::new_v4().into_bytes();
        let generation = u64::from_le_bytes(
            bytes[..8]
                .try_into()
                .expect("UUID prefix is exactly 8 bytes"),
        ) & i64::MAX as u64;
        if generation != 0 {
            return generation;
        }
    }
}

fn rebuild_entries(target: &Path, policy: RetentionPolicy) -> Result<retention::RetainedHistory> {
    let mut builder = RetentionBuilder::new(policy)?;
    super::run_summary_store::visit_run_summary_entries_for_index(target, |entry| {
        builder.push(RunHistoryIndexEntry::from_summary_entry(&entry))
    })?;
    builder.finish()
}

#[cfg(test)]
pub(super) fn rebuild_with_policy(target: &Path, max_rows: usize, max_bytes: u64) -> Result<()> {
    let guard = super::run_ledger::acquire_run_history_index_lock(target)?;
    quarantine_invalid_dirty_marker(target)?;
    rebuild_index(
        target,
        RetentionPolicy {
            max_rows,
            max_bytes,
        },
    )?;
    clear_run_history_dirty(target, &guard)
}

#[derive(Debug, PartialEq, Eq)]
enum DirtyMarkerState {
    Clean,
    Dirty,
    Invalid,
}

fn dirty_marker_state(target: &Path) -> Result<DirtyMarkerState> {
    let path = checked_run_history_dirty_path(target)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() => Ok(DirtyMarkerState::Dirty),
        Ok(_) => Ok(DirtyMarkerState::Invalid),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(DirtyMarkerState::Clean),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn quarantine_invalid_dirty_marker(target: &Path) -> Result<()> {
    if dirty_marker_state(target)? != DirtyMarkerState::Invalid {
        return Ok(());
    }
    let source = checked_run_history_dirty_path(target)?;
    let destination = invalid_dirty_marker_quarantine(&source)?;
    anyhow::ensure!(
        !destination.exists(),
        "run-history dirty-marker quarantine already exists: {}",
        destination.display()
    );
    fs::rename(&source, &destination).with_context(|| {
        format!(
            "Could not quarantine invalid run-history dirty marker {}",
            source.display()
        )
    })?;
    crate::fs_atomic::sync_parent_dir(&destination)?;
    Ok(())
}

fn invalid_dirty_marker_quarantine(source: &Path) -> Result<PathBuf> {
    let parent = source
        .parent()
        .context("run-history dirty marker has no parent")?;
    Ok(parent.join("run-history.index.dirty.invalid"))
}
