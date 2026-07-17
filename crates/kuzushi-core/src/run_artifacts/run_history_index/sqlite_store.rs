mod database;
mod entry_rows;
mod paging;
#[cfg(test)]
mod tests;

use super::super::{
    checked_legacy_run_history_index_path, checked_run_history_index_path, RunSummary,
};
use super::model::RunHistoryIndexEntry;
use super::retention::{
    entry_digest, retain_canonical_prefix, xor_digest, RetainedHistory, RetentionPolicy,
};
use anyhow::{Context, Result};
use rusqlite::Connection;
use std::fs;
use std::path::Path;

pub(super) use database::DirectoryStamp as DirectoryStampToken;

pub(super) const MAX_PAGE_WINDOW: usize = 10_000;
pub(super) const MAX_COMPATIBILITY_OFFSET: usize = 1_024;
pub(super) use paging::{is_stale_cursor_error, read_index_after, read_index_window};

pub(super) fn read_current_prefix(
    target: &Path,
    limit: usize,
) -> Result<super::CurrentRunHistoryPrefix> {
    let connection = database::open_index(target, false)?;
    database::validate_schema(&connection)?;
    let metadata = database::IndexMetadata::load(&connection)?;
    metadata.validate_header()?;
    let before = database::directory_stamp(target)?;
    anyhow::ensure!(metadata.stamp == before, "run-history index is stale");
    let entries = entry_rows::read_offset(&connection, 0, limit)?;
    validate_prefix_rows(&metadata, &entries, limit)?;
    anyhow::ensure!(
        before == database::directory_stamp(target)?,
        "run-history changed"
    );
    Ok(super::CurrentRunHistoryPrefix {
        entries,
        canonical_total: metadata.canonical_total,
        generation: metadata.generation,
    })
}

fn validate_prefix_rows(
    metadata: &database::IndexMetadata,
    entries: &[RunHistoryIndexEntry],
    limit: usize,
) -> Result<()> {
    let expected = usize::try_from(metadata.retained_count)
        .unwrap_or(usize::MAX)
        .min(limit);
    anyhow::ensure!(
        entries.len() == expected,
        "run-history prefix is incomplete"
    );
    for entry in entries {
        entry.validate()?;
    }
    anyhow::ensure!(
        entries.windows(2).all(|pair| pair[0] <= pair[1]),
        "run-history prefix is unsorted"
    );
    Ok(())
}

pub(super) fn validate_current_index(target: &Path) -> Result<()> {
    let _ = open_validated_index(target, false)?;
    Ok(())
}

pub(super) fn current_generation(target: &Path) -> Result<u64> {
    let (_, metadata, _) = open_validated_index(target, false)?;
    Ok(metadata.generation)
}

pub(super) fn capture_directory_stamp(target: &Path) -> Result<DirectoryStampToken> {
    database::directory_stamp(target)
}

pub(super) fn stored_retention_policy(target: &Path) -> Result<RetentionPolicy> {
    let connection = database::open_index(target, false)?;
    database::validate_schema(&connection)?;
    let metadata = database::IndexMetadata::load(&connection)?;
    metadata.validate_header()?;
    Ok(metadata.policy)
}

pub(super) fn upsert_summary(
    target: &Path,
    summary: &RunSummary,
    previous_was_missing: bool,
) -> Result<()> {
    let (mut connection, metadata, current) = open_validated_index(target, true)?;
    let stamp = metadata.stamp;
    let entry = RunHistoryIndexEntry::ready(summary);
    let mut canonical_xor = metadata.canonical_xor;
    if previous_was_missing {
        replace_canonical_digest(
            &mut canonical_xor,
            &RunHistoryIndexEntry::missing(&summary.run_id),
            &entry,
        )?;
    } else {
        let previous = current
            .iter()
            .find(|candidate| candidate.run_id == summary.run_id)
            .context("run-history summary update is outside the retained index window")?;
        replace_canonical_digest(&mut canonical_xor, previous, &entry)?;
    }
    update_retained_index(
        target,
        &mut connection,
        stamp,
        metadata.canonical_total,
        canonical_xor,
        metadata.policy,
        next_metadata_generation(metadata.generation)?,
        replace_entry(current, entry),
    )
}

pub(super) fn upsert_missing_run(target: &Path, run_id: &str) -> Result<()> {
    let (mut connection, metadata, current) = open_index_for_new_directory(target)?;
    let entry = RunHistoryIndexEntry::missing(run_id);
    let mut canonical_xor = metadata.canonical_xor;
    xor_digest(&mut canonical_xor, &entry_digest(&entry)?);
    let canonical_total = metadata
        .canonical_total
        .checked_add(1)
        .context("run-history canonical total overflowed")?;
    let snapshot = database::stable_directory_snapshot(target)?;
    anyhow::ensure!(
        snapshot.entry_count == canonical_total,
        "run-history directory count changed outside the indexed writer"
    );
    update_retained_index(
        target,
        &mut connection,
        snapshot.stamp,
        canonical_total,
        canonical_xor,
        metadata.policy,
        next_metadata_generation(metadata.generation)?,
        replace_entry(current, entry),
    )
}

pub(super) fn replace_index(
    target: &Path,
    retained: &RetainedHistory,
    policy: RetentionPolicy,
    generation: u64,
    stamp: DirectoryStampToken,
) -> Result<()> {
    let index_path = checked_run_history_index_path(target)?;
    database::reject_index_symlink(&index_path)?;
    let parent = index_path
        .parent()
        .context("run-history index has no parent")?;
    fs::create_dir_all(parent)?;
    let temp = tempfile::Builder::new()
        .prefix(".run-history-index-rebuild-")
        .tempfile_in(parent)?
        .into_temp_path();
    build_replacement_index(temp.as_ref(), retained, policy, generation, stamp)?;
    database::publish_replacement(temp.as_ref(), &index_path).with_context(|| {
        format!(
            "Could not publish run-history index {}",
            index_path.display()
        )
    })?;
    crate::fs_atomic::sync_parent_dir(&index_path)?;
    ensure_directory_stamp_unchanged(target, stamp)?;
    Ok(())
}

pub(super) fn remove_legacy_index_after_rebuild(target: &Path) -> Result<()> {
    let path = checked_legacy_run_history_index_path(target)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Ok(()),
        Ok(_) => {
            fs::remove_file(&path)?;
            crate::fs_atomic::sync_parent_dir(&path)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn open_validated_index(
    target: &Path,
    writable: bool,
) -> Result<(
    Connection,
    database::IndexMetadata,
    Vec<RunHistoryIndexEntry>,
)> {
    let connection = database::open_index(target, writable)?;
    database::validate_schema(&connection)?;
    let metadata = database::IndexMetadata::load(&connection)?;
    metadata.validate_header()?;
    let entries = entry_rows::load_all_bounded(&connection, metadata.policy.max_rows)?;
    metadata.validate(target, &entries)?;
    Ok((connection, metadata, entries))
}

fn open_index_for_new_directory(
    target: &Path,
) -> Result<(
    Connection,
    database::IndexMetadata,
    Vec<RunHistoryIndexEntry>,
)> {
    let connection = database::open_index(target, true)?;
    database::validate_schema(&connection)?;
    let metadata = database::IndexMetadata::load(&connection)?;
    metadata.validate_header()?;
    let entries = entry_rows::load_all_bounded(&connection, metadata.policy.max_rows)?;
    metadata.validate_rows(target, &entries)?;
    Ok((connection, metadata, entries))
}

fn update_retained_index(
    target: &Path,
    connection: &mut Connection,
    stamp: DirectoryStampToken,
    canonical_total: u64,
    canonical_xor: [u8; 32],
    policy: RetentionPolicy,
    generation: u64,
    candidates: Vec<RunHistoryIndexEntry>,
) -> Result<()> {
    let (entries, _) = retain_canonical_prefix(candidates, policy)?;
    let metadata = database::IndexMetadata::from_entries(
        stamp,
        canonical_total,
        canonical_xor,
        policy,
        generation,
        &entries,
    )?;
    let transaction = connection.transaction()?;
    entry_rows::replace_all(&transaction, &entries)?;
    metadata.write(&transaction)?;
    transaction.commit()?;
    database::sync_index_file(target)?;
    ensure_directory_stamp_unchanged(target, stamp)
}

fn build_replacement_index(
    path: &Path,
    retained: &RetainedHistory,
    policy: RetentionPolicy,
    generation: u64,
    stamp: DirectoryStampToken,
) -> Result<()> {
    let mut connection = database::open_path(path, true)?;
    database::initialize_schema(&connection)?;
    let metadata = database::IndexMetadata::from_entries(
        stamp,
        retained.canonical_total,
        retained.canonical_xor,
        policy,
        generation,
        &retained.entries,
    )?;
    anyhow::ensure!(
        metadata.retained_bytes == retained.retained_bytes,
        "run-history rebuild retained-byte accounting diverged"
    );
    let transaction = connection.transaction()?;
    entry_rows::replace_all(&transaction, &retained.entries)?;
    metadata.write(&transaction)?;
    transaction.commit()?;
    connection.close().map_err(|(_, error)| error)?;
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn replace_entry(
    mut entries: Vec<RunHistoryIndexEntry>,
    replacement: RunHistoryIndexEntry,
) -> Vec<RunHistoryIndexEntry> {
    entries.retain(|entry| entry.run_id != replacement.run_id);
    entries.push(replacement);
    entries
}

fn replace_canonical_digest(
    canonical_xor: &mut [u8; 32],
    previous: &RunHistoryIndexEntry,
    next: &RunHistoryIndexEntry,
) -> Result<()> {
    xor_digest(canonical_xor, &entry_digest(previous)?);
    xor_digest(canonical_xor, &entry_digest(next)?);
    Ok(())
}

fn next_metadata_generation(current: u64) -> Result<u64> {
    current
        .checked_add(1)
        .context("run-history generation overflowed")
}

fn ensure_directory_stamp_unchanged(target: &Path, expected: DirectoryStampToken) -> Result<()> {
    anyhow::ensure!(
        database::directory_stamp(target)? == expected,
        "run-history directory changed during index update"
    );
    Ok(())
}
