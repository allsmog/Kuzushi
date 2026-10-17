use super::canonical_run_files::{
    ensure_canonical_run_files, restore_canonical_run_file_placeholders,
};
use super::run_reproducibility_metadata::{
    summary_with_dynamic_metadata, summary_with_lifecycle_metadata,
};
use super::{
    checked_latest_run_path, checked_run_artifact_path, checked_runs_root, RunArtifact, RunSummary,
};
use crate::artifact_contract::{canonical_run_artifact_spec, CanonicalRunArtifactSpec};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_LATEST_RUN_POINTER_BYTES: usize = 256;
const RECOVERED_INTERRUPTION_ARTIFACTS: [&str; 6] = [
    "result.json",
    "failures.json",
    "artifacts.json",
    "events.jsonl",
    "items.jsonl",
    "report.md",
];

#[derive(Debug, Clone, PartialEq)]
pub struct RunSummaryEntry {
    pub run_id: String,
    pub path: PathBuf,
    pub state: RunSummaryEntryState,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RunSummaryEntryState {
    Ready(RunSummary),
    Issue(RunSummaryIssue),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "kind", content = "detail")]
pub enum RunSummaryIssue {
    InvalidRunId(String),
    UnsafeSymlink,
    NotDirectory,
    MissingMetadata,
    NonFileMetadata,
    UnreadableMetadata(String),
    InvalidMetadata(String),
    RunIdMismatch { metadata_run_id: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct RunSummaryEntriesCursorPage {
    pub entries: Vec<RunSummaryEntry>,
    pub next_cursor: Option<super::RunHistoryCursor>,
    pub history: super::RunHistoryPageInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredRun {
    pub run_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RunSummaryEntriesRead {
    pub entries: Vec<RunSummaryEntry>,
    /// Repairs performed by this read. Already-recovered interrupted runs do
    /// not reappear here on later reads.
    pub newly_recovered: Vec<RecoveredRun>,
}

#[derive(Debug, Default)]
struct RepairJournal {
    newly_recovered: Vec<RecoveredRun>,
}

#[derive(Debug, Clone)]
pub(crate) struct CurrentRunSummaryPrefix {
    pub entries: Vec<RunSummaryEntry>,
    pub canonical_total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LatestRunPointerState {
    Missing,
    Ready(super::RunId),
    Invalid(LatestRunPointerIssue),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LatestRunPointerIssue {
    UnsafePath(String),
    NotFile,
    Unreadable(String),
    Empty,
    InvalidRunId(String),
    MissingRunMetadata,
}

pub fn write_run_summary(target: impl AsRef<Path>, summary: &RunSummary) -> Result<PathBuf> {
    let target = target.as_ref();
    super::ensure_run_dir(target, &summary.run_id)?;
    let history_guard = begin_run_history_update(target);
    let (summary_path, summary, transition) = write_run_summary_snapshot(target, summary)?;
    ensure_canonical_run_files(target, &summary.run_id, &summary.status)?;
    finish_run_history_update(target, &summary, transition, history_guard.as_ref());
    write_latest_run_id(target, &summary)?;
    Ok(summary_path)
}

fn begin_run_history_update(target: &Path) -> Option<crate::file_lock::ExclusiveFileLock> {
    let guard = super::run_ledger::acquire_run_history_index_lock(target).ok()?;
    if super::run_history_index::prepare_run_history_update_under_lock(target, &guard).is_err() {
        return None;
    }
    Some(guard)
}

fn finish_run_history_update(
    target: &Path,
    summary: &RunSummary,
    transition: super::run_history_index::SummaryIndexTransition,
    guard: Option<&crate::file_lock::ExclusiveFileLock>,
) {
    let Some(guard) = guard else {
        let _ = super::run_history_index::mark_run_history_dirty_best_effort(target);
        return;
    };
    if super::run_history_index::update_run_history_index_under_lock(
        target, summary, transition, guard,
    )
    .is_ok()
        && super::run_history_index::clear_run_history_dirty(target, guard).is_err()
    {
        let _ = super::run_history_index::mark_run_history_dirty_best_effort(target);
    }
}

fn write_run_summary_snapshot(
    target: &Path,
    summary: &RunSummary,
) -> Result<(
    PathBuf,
    RunSummary,
    super::run_history_index::SummaryIndexTransition,
)> {
    let _guard = super::run_ledger::acquire_run_ledger_lock(target, &summary.run_id)?;
    let metadata_path =
        checked_run_artifact_path(target, &summary.run_id, run_metadata_artifact_spec().leaf)?;
    let (summary, transition) = summary_for_write(target, &metadata_path, summary);
    let run_id = summary.run_id.clone();
    let summary = summary_with_normalized_artifacts(target, &run_id, summary);
    super::process_identity::persist_running_identity_best_effort(target, &summary);
    let summary_path = write_run_summary_file(&metadata_path, &summary)?;
    Ok((summary_path, summary, transition))
}

fn summary_for_write(
    target: &Path,
    path: &Path,
    summary: &RunSummary,
) -> (RunSummary, super::run_history_index::SummaryIndexTransition) {
    let Some(existing) = read_run_summary_file(target, &summary.run_id, path) else {
        let transition = summary_index_transition_for_unreadable_path(path);
        return (summary_with_dynamic_metadata(target, summary), transition);
    };
    let mut next = summary.clone();
    next.started_at_unix = existing.started_at_unix;
    next = next.with_reproducibility_from(&existing);
    (
        summary_with_lifecycle_metadata(target, &next),
        super::run_history_index::SummaryIndexTransition::Existing,
    )
}

fn summary_index_transition_for_unreadable_path(
    path: &Path,
) -> super::run_history_index::SummaryIndexTransition {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            super::run_history_index::SummaryIndexTransition::MissingMetadata
        }
        _ => super::run_history_index::SummaryIndexTransition::Rebuild,
    }
}

pub fn load_run_summary(target: impl AsRef<Path>, run_id: &str) -> Result<RunSummary> {
    let target = target.as_ref();
    let (path, summary) = load_run_summary_raw(target, run_id)?;
    repair_stale_running_summary(target, &path, summary).map(|repair| repair.summary)
}

fn load_run_summary_raw(target: &Path, run_id: &str) -> Result<(PathBuf, RunSummary)> {
    let (path, body) = super::run_artifact_reader::read_run_artifact_text_required(
        target,
        run_id,
        run_metadata_artifact_spec().leaf,
        "Run metadata",
    )?;
    let summary = parse_run_summary_body(target, run_id, &body, &path)?;
    if summary.run_id != run_id {
        anyhow::bail!(
            "Run metadata runId {:?} does not match requested run id {run_id:?}: {}",
            summary.run_id,
            path.display()
        );
    }
    Ok((path, summary))
}

pub fn load_run_summary_without_repair(target: &Path, run_id: &str) -> Result<RunSummary> {
    load_run_summary_raw(target, run_id).map(|(_, summary)| summary)
}

pub(super) fn recover_published_terminal_under_lock(
    target: &Path,
    summary: RunSummary,
) -> Result<RunSummary> {
    if summary.status != "running" {
        return Ok(summary);
    }
    let projection = crate::run_lifecycle::load_run_projection_unhydrated(target, &summary.run_id)?;
    if projection.terminal.is_none() {
        return Ok(summary);
    }
    recover_summary_from_terminal_intent(target, summary, &projection)
}

pub fn read_latest_run_pointer(target: impl AsRef<Path>) -> Result<LatestRunPointerState> {
    let target = target.as_ref();
    let path = match checked_latest_run_path(target) {
        Ok(path) => path,
        Err(error) => return Ok(latest_pointer_unsafe_error(error)),
    };
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LatestRunPointerState::Missing);
        }
        Err(error) => return Ok(latest_pointer_unreadable(error)),
    };
    if metadata.file_type().is_symlink() {
        return Ok(latest_pointer_unsafe_path(&path));
    }
    if !metadata.is_file() {
        return Ok(LatestRunPointerState::Invalid(
            LatestRunPointerIssue::NotFile,
        ));
    }
    read_latest_run_pointer_file(target, &path)
}

fn read_latest_run_pointer_file(target: &Path, path: &Path) -> Result<LatestRunPointerState> {
    let body = match crate::bounded_file::read_utf8_text(path, MAX_LATEST_RUN_POINTER_BYTES) {
        Ok(body) => body,
        Err(error) => return Ok(latest_pointer_unreadable(error)),
    };
    let value = body.trim();
    if value.is_empty() {
        return Ok(LatestRunPointerState::Invalid(LatestRunPointerIssue::Empty));
    }
    let run_id = match super::RunId::parse(value) {
        Ok(run_id) => run_id,
        Err(error) => {
            return Ok(LatestRunPointerState::Invalid(
                LatestRunPointerIssue::InvalidRunId(error.to_string()),
            ));
        }
    };
    let metadata = match checked_run_artifact_path(target, run_id.as_str(), "run.json") {
        Ok(path) => path,
        Err(error) => return Ok(latest_pointer_unsafe_error(error)),
    };
    if !metadata.is_file() {
        return Ok(LatestRunPointerState::Invalid(
            LatestRunPointerIssue::MissingRunMetadata,
        ));
    }
    Ok(LatestRunPointerState::Ready(run_id))
}

fn latest_pointer_unreadable(error: std::io::Error) -> LatestRunPointerState {
    LatestRunPointerState::Invalid(LatestRunPointerIssue::Unreadable(error.to_string()))
}

fn latest_pointer_unsafe_error(error: anyhow::Error) -> LatestRunPointerState {
    LatestRunPointerState::Invalid(LatestRunPointerIssue::UnsafePath(error.to_string()))
}

fn latest_pointer_unsafe_path(path: &Path) -> LatestRunPointerState {
    LatestRunPointerState::Invalid(LatestRunPointerIssue::UnsafePath(format!(
        "Latest run pointer must not be a symlink: {}",
        path.display()
    )))
}

pub fn list_run_summaries(target: impl AsRef<Path>) -> Result<Vec<RunSummary>> {
    let mut summaries = list_run_summary_entries(target)?
        .into_iter()
        .filter_map(|entry| match entry.state {
            RunSummaryEntryState::Ready(summary) => Some(summary),
            RunSummaryEntryState::Issue(_) => None,
        })
        .collect::<Vec<_>>();
    sort_run_summaries(&mut summaries);
    Ok(summaries)
}

pub fn list_run_summary_entries(target: impl AsRef<Path>) -> Result<Vec<RunSummaryEntry>> {
    let mut repairs = RepairJournal::default();
    scan_run_summary_entries(target.as_ref(), true, &mut repairs)
}

/// Report whether run history exists without repairing stale running entries.
/// Startup routing uses this before recovery-aware hydration, so the repairing
/// read can also deliver the transition notice.
pub fn run_summary_history_exists(target: impl AsRef<Path>) -> Result<bool> {
    let mut repairs = RepairJournal::default();
    Ok(!scan_run_summary_entries(target.as_ref(), false, &mut repairs)?.is_empty())
}

pub(super) fn scan_run_summary_entries_for_index(target: &Path) -> Result<Vec<RunSummaryEntry>> {
    let mut entries = Vec::new();
    visit_run_summary_entries_for_index(target, |entry| {
        entries.push(entry);
        Ok(())
    })?;
    entries.sort_by(compare_run_summary_entries);
    Ok(entries)
}

pub(super) fn visit_run_summary_entries_for_index(
    target: &Path,
    mut visit: impl FnMut(RunSummaryEntry) -> Result<()>,
) -> Result<()> {
    let root = checked_runs_root(target)?;
    if !root.exists() {
        return Ok(());
    }
    let mut repairs = RepairJournal::default();
    for entry in
        fs::read_dir(&root).with_context(|| format!("Could not read {}", root.display()))?
    {
        visit(read_run_summary_entry(target, &entry?, false, &mut repairs))?;
    }
    Ok(())
}

fn scan_run_summary_entries(
    target: &Path,
    repair_stale: bool,
    repairs: &mut RepairJournal,
) -> Result<Vec<RunSummaryEntry>> {
    let root = checked_runs_root(target)?;
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(&root).with_context(|| format!("Could not read {}", root.display()))?
    {
        let entry = entry?;
        entries.push(read_run_summary_entry(
            target,
            &entry,
            repair_stale,
            repairs,
        ));
    }
    entries.sort_by(compare_run_summary_entries);
    Ok(entries)
}

/// Return one stable page of the canonical run-history ordering. The full-history
/// API remains available to CLI/export callers; interactive views should request
/// only the page they can display. If retention has truncated the derived index,
/// this fails closed because no bounded read can exclude a reordered evicted run;
/// callers may explicitly choose [`list_run_summary_entries`] for a full scan.
pub fn list_run_summary_entries_page(
    target: impl AsRef<Path>,
    offset: usize,
    limit: usize,
) -> Result<Vec<RunSummaryEntry>> {
    Ok(list_run_summary_entries_page_with_recoveries(target, offset, limit)?.entries)
}

fn list_run_summary_entries_page_without_repair(
    target: impl AsRef<Path>,
    offset: usize,
    limit: usize,
) -> Result<Vec<RunSummaryEntry>> {
    Ok(list_run_summary_entries_page_read(target, offset, limit, false)?.entries)
}

fn list_run_summary_entries_page_with_recoveries(
    target: impl AsRef<Path>,
    offset: usize,
    limit: usize,
) -> Result<RunSummaryEntriesRead> {
    list_run_summary_entries_page_read(target, offset, limit, true)
}

fn list_run_summary_entries_page_read(
    target: impl AsRef<Path>,
    offset: usize,
    limit: usize,
    repair_stale: bool,
) -> Result<RunSummaryEntriesRead> {
    if limit == 0 {
        return Ok(RunSummaryEntriesRead {
            entries: Vec::new(),
            newly_recovered: Vec::new(),
        });
    }
    let target = target.as_ref();
    let mut repairs = RepairJournal::default();
    let indexed = super::run_history_index::load_run_history_page(target, offset, limit)?;
    let entries = match materialize_indexed_page(target, &indexed, repair_stale, &mut repairs)? {
        Some(entries) => entries,
        None => {
            let rebuilt = super::run_history_index::rebuild_then_load_page(target, offset, limit)?;
            require_matching_indexed_page(target, &rebuilt, repair_stale, &mut repairs)?
        }
    };
    Ok(RunSummaryEntriesRead {
        entries,
        newly_recovered: repairs.newly_recovered,
    })
}

/// Return a generation-bound cursor page when the bounded index contains the
/// complete canonical history. Truncated retention fails closed; use
/// [`list_run_summary_entries`] only when an explicit full scan is acceptable.
pub fn list_run_summary_entries_cursor_page(
    target: impl AsRef<Path>,
    cursor: Option<&super::RunHistoryCursor>,
    limit: usize,
) -> Result<RunSummaryEntriesCursorPage> {
    let target = target.as_ref();
    let mut repairs = RepairJournal::default();
    let indexed = super::run_history_index::load_run_history_cursor_page(target, cursor, limit)?;
    if let Some(entries) = materialize_indexed_page(target, &indexed, true, &mut repairs)? {
        return Ok(public_cursor_page(indexed, entries));
    }
    let rebuilt = super::run_history_index::rebuild_then_load_cursor_page(target, cursor, limit)?;
    let entries = require_matching_indexed_page(target, &rebuilt, true, &mut repairs)?;
    Ok(public_cursor_page(rebuilt, entries))
}

pub fn list_recent_run_summary_entries(
    target: impl AsRef<Path>,
    limit: usize,
) -> Result<Vec<RunSummaryEntry>> {
    list_run_summary_entries_page_without_repair(target, 0, limit)
}

pub fn list_recent_run_summary_entries_with_recoveries(
    target: impl AsRef<Path>,
    limit: usize,
) -> Result<RunSummaryEntriesRead> {
    list_run_summary_entries_page_with_recoveries(target, 0, limit)
}

pub(crate) fn list_current_run_summary_prefix(
    target: impl AsRef<Path>,
    limit: usize,
) -> Result<Option<CurrentRunSummaryPrefix>> {
    let target = target.as_ref();
    let Some(indexed) = super::run_history_index::load_current_run_history_prefix(target, limit)?
    else {
        return Ok(None);
    };
    let Some(entries) = materialize_current_prefix(target, indexed.entries)? else {
        return Ok(None);
    };
    let current = super::run_history_index::load_current_run_history_prefix(target, 0)?;
    if !current.is_some_and(|current| current.generation == indexed.generation) {
        return Ok(None);
    }
    Ok(Some(CurrentRunSummaryPrefix {
        entries,
        canonical_total: indexed.canonical_total,
    }))
}

fn materialize_current_prefix(
    target: &Path,
    indexed: Vec<super::run_history_index::RunHistoryIndexEntry>,
) -> Result<Option<Vec<RunSummaryEntry>>> {
    let mut entries = Vec::with_capacity(indexed.len());
    let mut repairs = RepairJournal::default();
    for expected in indexed {
        let actual = read_indexed_run_summary_entry(target, expected.clone(), false, &mut repairs)?;
        if !indexed_ordering_key_matches(&expected, &actual) {
            return Ok(None);
        }
        entries.push(actual);
    }
    Ok(Some(entries))
}

fn read_run_summary_entry(
    target: &Path,
    entry: &fs::DirEntry,
    repair_stale: bool,
    repairs: &mut RepairJournal,
) -> RunSummaryEntry {
    let run_id = entry.file_name().to_string_lossy().into_owned();
    let path = entry.path();
    let state = run_summary_entry_state(target, entry, &run_id, repair_stale, repairs);
    RunSummaryEntry {
        run_id,
        path,
        state,
    }
}

fn run_summary_entry_state(
    target: &Path,
    entry: &fs::DirEntry,
    run_id: &str,
    repair_stale: bool,
    repairs: &mut RepairJournal,
) -> RunSummaryEntryState {
    if let Err(error) = super::RunId::parse(run_id) {
        return RunSummaryEntryState::Issue(RunSummaryIssue::InvalidRunId(error.to_string()));
    }
    match entry.file_type() {
        Ok(kind) if kind.is_symlink() => issue(RunSummaryIssue::UnsafeSymlink),
        Ok(kind) if !kind.is_dir() => issue(RunSummaryIssue::NotDirectory),
        Ok(_) => read_run_metadata_entry(target, &entry.path(), run_id, repair_stale, repairs),
        Err(error) => issue(RunSummaryIssue::UnreadableMetadata(error.to_string())),
    }
}

fn read_run_metadata_entry(
    target: &Path,
    dir: &Path,
    run_id: &str,
    repair_stale: bool,
    repairs: &mut RepairJournal,
) -> RunSummaryEntryState {
    let path = dir.join(run_metadata_artifact_spec().leaf);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            issue(RunSummaryIssue::MissingMetadata)
        }
        Err(error) => issue(RunSummaryIssue::UnreadableMetadata(error.to_string())),
        Ok(metadata) if metadata.file_type().is_symlink() => issue(RunSummaryIssue::UnsafeSymlink),
        Ok(metadata) if !metadata.is_file() => issue(RunSummaryIssue::NonFileMetadata),
        Ok(_) => parse_run_summary_entry(target, &path, run_id, repair_stale, repairs),
    }
}

fn parse_run_summary_entry(
    target: &Path,
    path: &Path,
    run_id: &str,
    repair_stale: bool,
    repairs: &mut RepairJournal,
) -> RunSummaryEntryState {
    let read = super::read_run_artifact_text(target, run_id, run_metadata_artifact_spec().leaf);
    let body = match read.require("Run metadata") {
        Ok((_, body)) => body,
        Err(error) => return issue(RunSummaryIssue::UnreadableMetadata(error.to_string())),
    };
    let summary = match parse_run_summary_body(target, run_id, &body, path) {
        Ok(summary) => summary,
        Err(error) => return issue(RunSummaryIssue::InvalidMetadata(error.to_string())),
    };
    if summary.run_id != run_id {
        return issue(RunSummaryIssue::RunIdMismatch {
            metadata_run_id: summary.run_id,
        });
    }
    if !repair_stale {
        return RunSummaryEntryState::Ready(summary);
    }
    match repair_stale_running_summary(target, path, summary) {
        Ok(repair) => {
            repairs.newly_recovered.extend(repair.recovered);
            RunSummaryEntryState::Ready(repair.summary)
        }
        Err(error) => issue(RunSummaryIssue::UnreadableMetadata(error.to_string())),
    }
}

fn read_indexed_run_summary_entry(
    target: &Path,
    indexed: super::run_history_index::RunHistoryIndexEntry,
    repair_stale: bool,
    repairs: &mut RepairJournal,
) -> Result<RunSummaryEntry> {
    let root = checked_runs_root(target)?;
    let path = root.join(&indexed.run_id);
    let state = indexed_run_summary_state(target, &path, &indexed, repair_stale, repairs);
    Ok(RunSummaryEntry {
        run_id: indexed.run_id,
        path,
        state,
    })
}

fn materialize_indexed_entries(
    target: &Path,
    indexed: &[super::run_history_index::RunHistoryIndexEntry],
    repair_stale: bool,
    repairs: &mut RepairJournal,
) -> Result<Option<Vec<RunSummaryEntry>>> {
    let mut entries = Vec::with_capacity(indexed.len());
    for expected in indexed {
        let actual =
            read_indexed_run_summary_entry(target, expected.clone(), repair_stale, repairs)?;
        if !indexed_ordering_key_matches(expected, &actual) {
            return Ok(None);
        }
        entries.push(actual);
    }
    Ok(Some(entries))
}

fn materialize_indexed_page(
    target: &Path,
    indexed: &super::run_history_index::IndexedRunHistoryPage,
    repair_stale: bool,
    repairs: &mut RepairJournal,
) -> Result<Option<Vec<RunSummaryEntry>>> {
    ensure_bounded_page_is_authentic(indexed)?;
    if !retained_ordering_witness_matches(target, &indexed.retained_entries)? {
        return Ok(None);
    }
    let Some(entries) =
        materialize_indexed_entries(target, &indexed.entries, repair_stale, repairs)?
    else {
        return Ok(None);
    };
    if !super::run_history_index::page_generation_is_current(target, indexed.info.generation) {
        return Ok(None);
    }
    Ok(Some(entries))
}

fn ensure_bounded_page_is_authentic(
    indexed: &super::run_history_index::IndexedRunHistoryPage,
) -> Result<()> {
    anyhow::ensure!(
        !indexed.info.truncated,
        "run-history retention is truncated, so a bounded page cannot prove that an evicted canonical run still sorts below the retained window; use `list_run_summary_entries` for an explicit full canonical scan"
    );
    Ok(())
}

fn require_matching_indexed_page(
    target: &Path,
    indexed: &super::run_history_index::IndexedRunHistoryPage,
    repair_stale: bool,
    repairs: &mut RepairJournal,
) -> Result<Vec<RunSummaryEntry>> {
    materialize_indexed_page(target, indexed, repair_stale, repairs)?
        .context("run-history index still disagrees with canonical run metadata after rebuild")
}

fn retained_ordering_witness_matches(
    target: &Path,
    retained: &[super::run_history_index::RunHistoryIndexEntry],
) -> Result<bool> {
    // The authenticity gate above guarantees this is an untruncated index, so
    // the bounded retained witness is also the complete canonical history.
    // Reading it prevents an unrequested row edit from reordering this page.
    let mut repairs = RepairJournal::default();
    for expected in retained {
        let actual = read_indexed_run_summary_entry(target, expected.clone(), false, &mut repairs)?;
        if !indexed_ordering_key_matches(expected, &actual) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn indexed_ordering_key_matches(
    indexed: &super::run_history_index::RunHistoryIndexEntry,
    actual: &RunSummaryEntry,
) -> bool {
    match (indexed.started_at_unix, &actual.state) {
        (Some(expected), RunSummaryEntryState::Ready(summary)) => {
            summary.run_id == indexed.run_id && summary.started_at_unix == expected
        }
        (None, RunSummaryEntryState::Issue(_)) => true,
        _ => false,
    }
}

fn public_cursor_page(
    indexed: super::run_history_index::IndexedRunHistoryPage,
    entries: Vec<RunSummaryEntry>,
) -> RunSummaryEntriesCursorPage {
    RunSummaryEntriesCursorPage {
        entries,
        next_cursor: indexed.next_cursor,
        history: indexed.info,
    }
}

fn indexed_run_summary_state(
    target: &Path,
    path: &Path,
    indexed: &super::run_history_index::RunHistoryIndexEntry,
    repair_stale: bool,
    repairs: &mut RepairJournal,
) -> RunSummaryEntryState {
    if let Err(error) = super::RunId::parse(&indexed.run_id) {
        return issue(
            indexed
                .issue
                .clone()
                .unwrap_or_else(|| RunSummaryIssue::InvalidRunId(error.to_string())),
        );
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => issue(RunSummaryIssue::UnsafeSymlink),
        Ok(metadata) if !metadata.is_dir() => issue(RunSummaryIssue::NotDirectory),
        Ok(_) => read_run_metadata_entry(target, path, &indexed.run_id, repair_stale, repairs),
        Err(error) => issue(RunSummaryIssue::UnreadableMetadata(error.to_string())),
    }
}

fn issue(value: RunSummaryIssue) -> RunSummaryEntryState {
    RunSummaryEntryState::Issue(value)
}

fn compare_run_summary_entries(
    left: &RunSummaryEntry,
    right: &RunSummaryEntry,
) -> std::cmp::Ordering {
    match (&left.state, &right.state) {
        (RunSummaryEntryState::Ready(left), RunSummaryEntryState::Ready(right)) => {
            compare_run_recency(right, left)
        }
        (RunSummaryEntryState::Ready(_), RunSummaryEntryState::Issue(_)) => {
            std::cmp::Ordering::Less
        }
        (RunSummaryEntryState::Issue(_), RunSummaryEntryState::Ready(_)) => {
            std::cmp::Ordering::Greater
        }
        (RunSummaryEntryState::Issue(_), RunSummaryEntryState::Issue(_)) => {
            left.run_id.cmp(&right.run_id)
        }
    }
}

fn read_run_summary_file(target: &Path, run_id: &str, expected_path: &Path) -> Option<RunSummary> {
    let read = super::read_run_artifact_text(target, run_id, run_metadata_artifact_spec().leaf);
    let super::RunArtifactRead::Ready { path, value } = read else {
        return None;
    };
    if path != expected_path {
        return None;
    }
    parse_run_summary_body(target, run_id, &value, &path).ok()
}

fn parse_run_summary_body(
    target: &Path,
    run_id: &str,
    body: &str,
    path: &Path,
) -> Result<RunSummary> {
    let value: Value = serde_json::from_str(body)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    if !value.is_object() {
        anyhow::bail!("Run metadata is not a JSON object: {}", path.display());
    }
    let summary = serde_json::from_value(value).map_err(|error| {
        anyhow::anyhow!("Run metadata is not canonical: {error}: {}", path.display())
    })?;
    let summary = summary_with_normalized_artifacts(target, run_id, summary);
    validate_run_summary_costs(&summary)
        .with_context(|| format!("Run metadata cost is invalid: {}", path.display()))?;
    Ok(summary)
}

fn summary_with_normalized_artifacts(
    target: &Path,
    run_id: &str,
    mut summary: RunSummary,
) -> RunSummary {
    summary.artifacts =
        super::run_artifact::normalize_run_artifact_identities(target, run_id, summary.artifacts);
    summary
}

fn run_metadata_artifact_spec() -> &'static CanonicalRunArtifactSpec {
    canonical_run_artifact_spec("run.json").expect("run metadata artifact must be in shared spec")
}

fn write_run_summary_file(path: &Path, summary: &RunSummary) -> Result<PathBuf> {
    validate_run_summary_costs(summary)?;
    reject_non_file_target(path, "Run metadata target")?;
    let body = format!("{}\n", serde_json::to_string_pretty(summary)?);
    crate::fs_atomic::write_atomic(path, &body)
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path.to_path_buf())
}

fn validate_run_summary_costs(summary: &RunSummary) -> Result<()> {
    summary.checked_cost_report()?;
    for call in &summary.llm_calls {
        if let Some(cost_usd) = call.cost_usd {
            crate::runtime::RuntimeCost::from_usd(cost_usd, "run summary LLM call cost")?;
        }
        if let Some(cost_usd) = call.observed_cost_usd {
            crate::runtime::RuntimeCost::from_usd(cost_usd, "run summary LLM call observed cost")?;
        }
        anyhow::ensure!(
            call.cost_usd.is_none() || call.observed_cost_usd.is_none(),
            "run summary LLM call cannot claim exact and unresolved cost"
        );
        anyhow::ensure!(
            call.observed_cost_usd.is_some() == call.provider_spend_unresolved,
            "run summary LLM call unresolved cost fields must appear together"
        );
        anyhow::ensure!(
            call.call_attempted != Some(false)
                || (call.cost_usd.is_none()
                    && call.observed_cost_usd.is_none()
                    && !call.provider_spend_unresolved),
            "run summary cannot attach spend to an explicitly unattempted LLM call"
        );
    }
    Ok(())
}

fn write_latest_run_id(target: &Path, summary: &RunSummary) -> Result<()> {
    let _guard = super::run_ledger::acquire_latest_pointer_lock(target)?;
    let path = checked_latest_run_path(target)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    reject_non_file_target(&path, "Latest run pointer target")?;
    if !candidate_is_latest(target, &path, summary) {
        return Ok(());
    }
    // The latest-run pointer is read to resolve the newest run; a torn write
    // here would desync the whole run index, so it goes through the atomic path.
    crate::fs_atomic::write_atomic(&path, &format!("{}\n", summary.run_id))
        .with_context(|| format!("Could not write {}", path.display()))
}

fn candidate_is_latest(target: &Path, latest_path: &Path, candidate: &RunSummary) -> bool {
    let Ok(current_id) =
        crate::bounded_file::read_utf8_text(latest_path, MAX_LATEST_RUN_POINTER_BYTES)
    else {
        return true;
    };
    let current_id = current_id.trim();
    if current_id == candidate.run_id {
        return false;
    }
    let Ok(current_path) =
        checked_run_artifact_path(target, current_id, run_metadata_artifact_spec().leaf)
    else {
        return true;
    };
    let Some(current) = read_run_summary_file(target, current_id, &current_path) else {
        return true;
    };
    compare_run_recency(candidate, &current).is_gt()
}

pub fn repair_latest_run_pointer(target: impl AsRef<Path>) -> Result<Option<String>> {
    let target = target.as_ref();
    let _guard = super::run_ledger::acquire_latest_pointer_lock(target)?;
    let latest_path = checked_latest_run_path(target)?;
    let mut summaries = scan_run_summary_entries_for_index(target)?
        .into_iter()
        .filter_map(|entry| match entry.state {
            RunSummaryEntryState::Ready(summary) => Some(summary),
            RunSummaryEntryState::Issue(_) => None,
        })
        .collect::<Vec<_>>();
    sort_run_summaries(&mut summaries);
    let Some(newest) = summaries.into_iter().next() else {
        return remove_latest_run_pointer(&latest_path);
    };
    if let Some(parent) = latest_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    reject_non_file_target(&latest_path, "Latest run pointer target")?;
    crate::fs_atomic::write_atomic(&latest_path, &format!("{}\n", newest.run_id))
        .with_context(|| format!("Could not write {}", latest_path.display()))?;
    Ok(Some(newest.run_id))
}

fn remove_latest_run_pointer(path: &Path) -> Result<Option<String>> {
    match fs::remove_file(path) {
        Ok(()) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Could not remove {}", path.display())),
    }
}

fn reject_non_file_target(path: &Path, label: &str) -> Result<()> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => anyhow::bail!("{label} is not a file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn sort_run_summaries(summaries: &mut [RunSummary]) {
    summaries.sort_by(|left, right| compare_run_recency(right, left));
}

fn compare_run_recency(left: &RunSummary, right: &RunSummary) -> std::cmp::Ordering {
    // Keep the seconds field schema-compatible while generated IDs provide
    // the finer tie-break needed by consecutive runs in the same second.
    left.started_at_unix
        .cmp(&right.started_at_unix)
        .then_with(|| {
            run_id_timestamp_millis(&left.run_id).cmp(&run_id_timestamp_millis(&right.run_id))
        })
        .then_with(|| left.run_id.cmp(&right.run_id))
}

fn run_id_timestamp_millis(run_id: &str) -> Option<u128> {
    let (without_suffix, _) = run_id.rsplit_once('-')?;
    let (_, timestamp) = without_suffix.rsplit_once('-')?;
    timestamp.parse().ok()
}

struct RunSummaryRepair {
    summary: RunSummary,
    recovered: Option<RecoveredRun>,
}

fn repair_stale_running_summary(
    target: &Path,
    _summary_path: &Path,
    summary: RunSummary,
) -> Result<RunSummaryRepair> {
    if !needs_run_truth_recovery(target, &summary) {
        return Ok(RunSummaryRepair {
            summary,
            recovered: None,
        });
    }
    let _guard = super::run_ledger::acquire_run_terminal_lock(target, &summary.run_id)?;
    let (_, current) = load_run_summary_raw(target, &summary.run_id)?;
    let transitioned_running = current.status == "running";
    let repaired = recover_run_truth_under_lock(target, current)?;
    let recovered =
        (transitioned_running && is_recovered_interruption(&repaired)).then(|| RecoveredRun {
            run_id: repaired.run_id.clone(),
            reason: repaired
                .error
                .clone()
                .unwrap_or_else(|| "run interrupted during process recovery".to_string()),
        });
    Ok(RunSummaryRepair {
        summary: repaired,
        recovered,
    })
}

fn needs_run_truth_recovery(target: &Path, summary: &RunSummary) -> bool {
    stale_running_process(target, summary).is_some()
        || is_recovered_interruption(summary)
        || super::terminal_intent::has_terminal_intent(target, &summary.run_id)
        || (summary.status != "running"
            && summary.terminal_result_sha256.is_some()
            && !super::terminal_intent::has_typed_terminal_marker(target, &summary.run_id))
}

fn recover_run_truth_under_lock(target: &Path, current: RunSummary) -> Result<RunSummary> {
    let projection = crate::run_lifecycle::load_run_projection_unhydrated(target, &current.run_id)?;
    if current.status == "running" && projection.terminal.is_some() {
        return recover_summary_from_terminal_intent(target, current, &projection);
    }
    // A completed recovery is terminal. Rewriting it would bump the history
    // generation on every read, so a generation-verified page could never
    // stabilize. Incomplete recovery artifacts still fall through and repair.
    if recovered_interruption_is_complete(target, &current) && projection.terminal.is_some() {
        mark_existing_terminal_if_present(target, &current, &projection)?;
        return Ok(current);
    }
    if current.status != "running" && !is_recovered_interruption(&current) {
        return recover_missing_typed_terminal(target, current, &projection);
    }
    let reason = interruption_reason(target, &current)?;
    let digest = super::tool_run_record::terminal_result_digest(
        "interrupted",
        &serde_json::json!({ "reason": reason }),
    );
    validate_recovery_digest(&current, &digest)?;
    let current_cost = current.checked_cost_report()?;
    let recovered_cost = if current_cost.is_unavailable() {
        super::lifecycle_cost::lifecycle_cost_report(target, &current.run_id)?
    } else {
        current_cost
    };
    let repaired = repaired_interruption(current, reason, digest, recovered_cost);
    persist_recovered_interruption(target, repaired)
}

fn recover_summary_from_terminal_intent(
    target: &Path,
    current: RunSummary,
    projection: &crate::run_lifecycle::RunProjection,
) -> Result<RunSummary> {
    let terminal = projection
        .terminal
        .as_ref()
        .context("typed terminal is missing")?;
    let intended = super::terminal_intent::load_terminal_intent(target, &current.run_id)?
        .context("typed terminal has no recoverable terminal intent")?;
    anyhow::ensure!(
        terminal.status.label() == intended.status,
        "typed terminal status does not match terminal intent for run {}",
        current.run_id
    );
    write_run_summary(target, &intended)?;
    super::terminal_intent::mark_typed_terminal(target, &current.run_id)?;
    super::terminal_intent::clear_terminal_intent_best_effort(target, &current.run_id);
    Ok(intended)
}

fn recover_missing_typed_terminal(
    target: &Path,
    current: RunSummary,
    projection: &crate::run_lifecycle::RunProjection,
) -> Result<RunSummary> {
    if let Some(terminal) = &projection.terminal {
        anyhow::ensure!(
            terminal.status.label() == current.status,
            "typed terminal disagrees with run summary for run {}",
            current.run_id
        );
    } else {
        let output = terminal_recovery_output(&current);
        let observation = crate::run_lifecycle::RunObservationHandle::jsonl(
            target.to_path_buf(),
            current.run_id.clone(),
        )?;
        crate::run_lifecycle::emit_terminal_outcome_for_summary(
            &observation,
            target,
            &current.run_id,
            &output,
            &current,
            None,
        )?;
    }
    super::terminal_intent::mark_typed_terminal(target, &current.run_id)?;
    super::terminal_intent::clear_terminal_intent_best_effort(target, &current.run_id);
    Ok(current)
}

fn mark_existing_terminal_if_present(
    target: &Path,
    current: &RunSummary,
    projection: &crate::run_lifecycle::RunProjection,
) -> Result<()> {
    if projection.terminal.is_some() {
        super::terminal_intent::mark_typed_terminal(target, &current.run_id)?;
        super::terminal_intent::clear_terminal_intent_best_effort(target, &current.run_id);
    }
    Ok(())
}

fn terminal_recovery_output(summary: &RunSummary) -> Value {
    serde_json::json!({
        "ok": matches!(summary.status.as_str(), "completed" | "skipped"),
        "status": summary.status,
        "summary": summary.error.as_deref().unwrap_or("tool run finished"),
        "artifacts": summary.artifacts,
        "warnings": [],
        "errors": summary.error.iter().collect::<Vec<_>>(),
        "data": { "recoveredTypedTerminal": true },
    })
}

fn recovered_interruption_is_complete(target: &Path, summary: &RunSummary) -> bool {
    is_recovered_interruption(summary)
        && summary.artifacts.iter().any(|artifact| {
            Path::new(&artifact.path)
                .file_name()
                .is_some_and(|leaf| leaf == "result.json")
        })
        && RECOVERED_INTERRUPTION_ARTIFACTS
            .iter()
            .all(|leaf| regular_run_artifact_exists(target, &summary.run_id, leaf))
}

fn regular_run_artifact_exists(target: &Path, run_id: &str, leaf: &str) -> bool {
    checked_run_artifact_path(target, run_id, leaf)
        .ok()
        .and_then(|path| fs::symlink_metadata(path).ok())
        .is_some_and(|metadata| metadata.is_file())
}

fn interruption_reason(target: &Path, summary: &RunSummary) -> Result<String> {
    if let Some(stale) = stale_running_process(target, summary) {
        return Ok(stale.reason());
    }
    summary
        .error
        .clone()
        .filter(|_| is_recovered_interruption(summary))
        .context("run is no longer eligible for interrupted recovery")
}

fn validate_recovery_digest(summary: &RunSummary, expected: &str) -> Result<()> {
    if summary.status == "running" {
        return Ok(());
    }
    anyhow::ensure!(
        summary.terminal_result_sha256.as_deref() == Some(expected),
        "run {} has a divergent interrupted recovery digest",
        summary.run_id
    );
    Ok(())
}

fn repaired_interruption(
    mut summary: RunSummary,
    reason: String,
    digest: String,
    recovered_cost: crate::runtime::RuntimeCostReport,
) -> RunSummary {
    if summary.status == "running" {
        summary = summary.interrupted(reason);
    }
    if summary
        .checked_cost_report()
        .is_ok_and(crate::runtime::RuntimeCostReport::is_unavailable)
    {
        summary = summary.with_cost_report(recovered_cost);
    }
    summary.with_terminal_result_sha256(Some(digest))
}

fn persist_recovered_interruption(target: &Path, mut repaired: RunSummary) -> Result<RunSummary> {
    restore_canonical_run_file_placeholders(target, &repaired.run_id, "interrupted")?;
    let reason = repaired
        .error
        .clone()
        .unwrap_or_else(|| "run interrupted".to_string());
    let artifact = preserve_or_write_recovered_result(target, &repaired.run_id, &reason)?;
    repaired = repaired.with_artifact(artifact);
    for artifact in super::load_run_artifacts(target, &repaired.run_id)? {
        repaired = repaired.with_artifact(artifact);
    }
    ensure_canonical_run_files(target, &repaired.run_id, "interrupted")?;
    crate::run_lifecycle::emit_recovered_interruption(
        target,
        &repaired.run_id,
        &reason,
        repaired.checked_cost_report()?,
    )?;
    super::tool_run_record_events::append_recovered_interruption_event(target, &repaired, &reason)?;
    write_run_summary(target, &repaired)?;
    super::terminal_intent::mark_typed_terminal(target, &repaired.run_id)?;
    super::terminal_intent::clear_terminal_intent_best_effort(target, &repaired.run_id);
    Ok(repaired)
}

fn preserve_or_write_recovered_result(
    target: &Path,
    run_id: &str,
    reason: &str,
) -> Result<RunArtifact> {
    if regular_run_artifact_exists(target, run_id, "result.json") {
        return RunArtifact::from_declared("tool result", "result.json", Some("json"))
            .context("canonical result artifact descriptor is invalid");
    }
    super::write_run_artifact_json(
        target,
        run_id,
        "result.json",
        "tool result",
        &super::prepared_model_input::attach(target, run_id, recovered_interruption_result(reason)),
    )
}

fn recovered_interruption_result(reason: &str) -> Value {
    serde_json::json!({
        "ok": false,
        "status": "interrupted",
        "summary": reason,
        "artifacts": [],
        "warnings": [],
        "errors": [reason],
        "data": { "recovered": true }
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StaleRunningProcess {
    process_id: u32,
    issue: super::process_identity::ProcessOwnershipIssue,
}

impl StaleRunningProcess {
    fn reason(self) -> String {
        match self.issue {
            super::process_identity::ProcessOwnershipIssue::ProcessDead => {
                dead_process_reason(self.process_id)
            }
            super::process_identity::ProcessOwnershipIssue::IdentityRejected(detail) => {
                unverified_process_owner_reason(self.process_id, &detail)
            }
        }
    }
}

fn stale_running_process(target: &Path, summary: &RunSummary) -> Option<StaleRunningProcess> {
    let process_id = summary.process_id?;
    if summary.status != "running" {
        return None;
    }
    match super::process_identity::original_process_status(target, &summary.run_id, process_id) {
        super::process_identity::OriginalProcessStatus::OriginalOwner => None,
        super::process_identity::OriginalProcessStatus::NotOwner(issue) => {
            Some(StaleRunningProcess { process_id, issue })
        }
    }
}

fn is_recovered_interruption(summary: &RunSummary) -> bool {
    summary.status == "interrupted"
        && summary.terminal_result_sha256.is_some()
        && summary
            .error
            .as_deref()
            .is_some_and(is_process_recovery_reason)
}

fn dead_process_reason(process_id: u32) -> String {
    format!("run process {process_id} is no longer running; marking summary interrupted")
}

fn is_dead_process_reason(reason: &str) -> bool {
    reason.starts_with("run process ")
        && reason.ends_with(" is no longer running; marking summary interrupted")
}

fn unverified_process_owner_reason(process_id: u32, detail: &str) -> String {
    format!(
        "run process {process_id} cannot be verified as the original owner ({detail}); marking summary interrupted"
    )
}

fn is_process_recovery_reason(reason: &str) -> bool {
    is_dead_process_reason(reason) || is_unverified_process_owner_reason(reason)
}

fn is_unverified_process_owner_reason(reason: &str) -> bool {
    reason.starts_with("run process ")
        && reason.contains(" cannot be verified as the original owner (")
        && reason.ends_with("); marking summary interrupted")
}

#[cfg(test)]
mod liveness_tests {
    use super::*;

    #[test]
    fn completed_summary_without_typed_terminal_is_reconciled() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "run-summary-before-terminal";
        let output = serde_json::json!({
            "ok": true,
            "status": "completed",
            "summary": "real result",
            "data": {"value": 7}
        });
        let digest = super::super::tool_run_record::terminal_result_digest("completed", &output);
        let summary = RunSummary::running(run_id, "tool", None, "target")
            .complete()
            .with_terminal_result_sha256(Some(digest));
        write_run_summary(target.path(), &summary).unwrap();
        let result_path = super::super::run_artifact_path(target.path(), run_id, "result.json");
        std::fs::write(&result_path, serde_json::to_vec(&output).unwrap()).unwrap();
        let original = std::fs::read(&result_path).unwrap();

        let repaired = load_run_summary(target.path(), run_id).unwrap();

        assert_eq!(repaired.status, "completed");
        assert_eq!(std::fs::read(&result_path).unwrap(), original);
        let projection = crate::run_lifecycle::load_run_projection(target.path(), run_id).unwrap();
        assert_eq!(
            projection
                .projection
                .terminal
                .map(|terminal| terminal.status),
            Some(crate::run_lifecycle::RunItemStatus::Completed)
        );
    }

    #[test]
    fn typed_terminal_without_terminal_summary_uses_the_atomic_intent() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "run-terminal-before-summary";
        let running = RunSummary::running(run_id, "tool", None, "target");
        write_run_summary(target.path(), &running).unwrap();
        let intended = running
            .complete()
            .with_terminal_result_sha256(Some("intent-digest".to_string()));
        super::super::terminal_intent::write_terminal_intent(target.path(), &intended).unwrap();
        let observation = crate::run_lifecycle::RunObservationHandle::jsonl(
            target.path().to_path_buf(),
            run_id.to_string(),
        )
        .unwrap();
        crate::run_lifecycle::emit_terminal_outcome_for_summary(
            &observation,
            target.path(),
            run_id,
            &serde_json::json!({"summary": "completed"}),
            &intended,
            None,
        )
        .unwrap();

        let repaired = load_run_summary(target.path(), run_id).unwrap();

        assert_eq!(repaired.status, "completed");
        assert_eq!(
            repaired.terminal_result_sha256.as_deref(),
            Some("intent-digest")
        );
        assert!(!super::super::terminal_intent::has_terminal_intent(
            target.path(),
            run_id
        ));
    }

    #[test]
    fn interrupted_recovery_preserves_an_existing_real_result() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "run-preserve-real-result";
        let running = RunSummary::running(run_id, "tool", None, "target").with_process_id(u32::MAX);
        write_run_summary(target.path(), &running).unwrap();
        let result_path = super::super::run_artifact_path(target.path(), run_id, "result.json");
        let real_result = br#"{"ok":true,"status":"completed","data":{"real":true}}"#;
        std::fs::write(&result_path, real_result).unwrap();

        let repaired = load_run_summary(target.path(), run_id).unwrap();

        assert_eq!(repaired.status, "interrupted");
        assert_eq!(std::fs::read(result_path).unwrap(), real_result);
    }

    #[test]
    fn current_process_is_alive() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(super::super::process_identity::original_process_is_alive(
            tmp.path(),
            "run-current-process",
            std::process::id()
        ));
    }

    #[cfg(unix)]
    #[test]
    fn reaped_child_process_is_not_alive() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!super::super::process_identity::original_process_is_alive(
            tmp.path(),
            "run-reaped-process",
            spawn_dead_process_id()
        ));
    }

    #[cfg(unix)]
    #[test]
    fn running_summary_with_dead_pid_is_repaired_to_interrupted() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-dead-pid";
        let summary = RunSummary::running("run-dead-pid", "scan", None, "target")
            .with_process_id(spawn_dead_process_id());
        write_run_summary(tmp.path(), &summary).unwrap();
        let loaded = list_run_summaries(tmp.path()).unwrap();
        assert_interrupted_summary(&loaded);
        assert_interrupted_run_artifacts(tmp.path(), run_id);
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_recovery_sums_only_terminal_model_call_costs() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-dead-pid-cost";
        let summary = RunSummary::running(run_id, "scan", None, "target")
            .with_process_id(spawn_dead_process_id());
        write_run_summary(tmp.path(), &summary).unwrap();
        append_recovery_cost_step(
            tmp.path(),
            run_id,
            1,
            "tool-loop preflight ok",
            Some(0.5),
            true,
        );
        append_recovery_cost_step(tmp.path(), run_id, 2, "model one", Some(0.01), false);
        append_recovery_cost_step(tmp.path(), run_id, 3, "model two", Some(0.02), false);
        append_recovery_cost_step(tmp.path(), run_id, 4, "summary", None, true);

        let repaired = load_run_summary(tmp.path(), run_id).unwrap();

        assert_eq!(repaired.status, "interrupted");
        assert!((repaired.cost_usd.unwrap() - 0.03).abs() < 1e-9);
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_recovery_preserves_incomplete_observed_lifecycle_cost() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-dead-pid-incomplete-cost";
        let summary = RunSummary::running(run_id, "scan", None, "target")
            .with_process_id(spawn_dead_process_id());
        write_run_summary(tmp.path(), &summary).unwrap();
        append_recovery_cost_step(tmp.path(), run_id, 1, "model one", Some(0.01), false);
        append_recovery_cost_step(tmp.path(), run_id, 2, "model two", None, false);

        let repaired = load_run_summary(tmp.path(), run_id).unwrap();

        assert_eq!(repaired.status, "interrupted");
        assert_eq!(repaired.cost_usd, None);
        assert_eq!(repaired.observed_cost_usd, Some(0.01));
        assert!(repaired.provider_spend_unresolved);
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_recovery_never_overwrites_existing_exact_cost() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-dead-pid-existing-cost";
        let summary = RunSummary::running(run_id, "scan", None, "target")
            .with_process_id(spawn_dead_process_id())
            .with_cost(Some(0.4));
        write_run_summary(tmp.path(), &summary).unwrap();
        append_recovery_cost_step(tmp.path(), run_id, 1, "model", Some(0.01), false);

        let repaired = load_run_summary(tmp.path(), run_id).unwrap();

        assert_eq!(repaired.status, "interrupted");
        assert_eq!(repaired.cost_usd, Some(0.4));
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_lifecycle_cost_overflow_fails_before_recovery_persistence() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-dead-pid-cost-overflow";
        let summary = RunSummary::running(run_id, "scan", None, "target")
            .with_process_id(spawn_dead_process_id());
        write_run_summary(tmp.path(), &summary).unwrap();
        append_recovery_cost_step(tmp.path(), run_id, 1, "model one", Some(f64::MAX), false);
        append_recovery_cost_step(tmp.path(), run_id, 2, "model two", Some(f64::MAX), false);

        assert!(load_run_summary(tmp.path(), run_id).is_err());
        let body = read_run_artifact(tmp.path(), run_id, "run.json");
        let persisted: RunSummary = serde_json::from_str(&body).unwrap();
        assert_eq!(persisted.status, "running");
        assert!(persisted.terminal_result_sha256.is_none());
    }

    #[cfg(unix)]
    fn append_recovery_cost_step(
        target: &Path,
        run_id: &str,
        sequence: usize,
        label: &str,
        cost_usd: Option<f64>,
        preflight: bool,
    ) {
        let writer = crate::run_lifecycle::RunItemWriter::open(target, run_id, None).unwrap();
        if preflight {
            append_recovery_preflight(writer, label);
            return;
        }
        append_recovery_model_step(writer, sequence, label, cost_usd);
    }

    #[cfg(unix)]
    fn append_recovery_preflight(writer: crate::run_lifecycle::RunItemWriter, label: &str) {
        use crate::run_lifecycle::*;
        let item = RunItemV1::DiagnosticNotice {
            level: DiagnosticLevel::Info,
            message: SafeText::operator_visible(label),
        };
        writer
            .emit_and_flush(RunItemRecord::new(
                RunItemId::new(),
                RunItemSource::Runtime,
                item,
            ))
            .unwrap();
        writer.shutdown().unwrap();
    }

    #[cfg(unix)]
    fn append_recovery_model_step(
        writer: crate::run_lifecycle::RunItemWriter,
        sequence: usize,
        label: &str,
        cost_usd: Option<f64>,
    ) {
        let item_id = crate::run_lifecycle::RunItemId::new();
        let call_id = crate::run_lifecycle::RunCallId::new();
        let record = |item| {
            crate::run_lifecycle::RunItemRecord::new(
                item_id,
                crate::run_lifecycle::RunItemSource::Runtime,
                item,
            )
            .with_call(call_id)
        };
        writer
            .emit_and_flush(record(recovery_model_start(label)))
            .unwrap();
        writer
            .emit_and_flush(record(recovery_model_finish(sequence, cost_usd)))
            .unwrap();
        writer.shutdown().unwrap();
    }

    #[cfg(unix)]
    fn recovery_model_start(label: &str) -> crate::run_lifecycle::RunItemV1 {
        use crate::run_lifecycle::*;
        RunItemV1::ModelCallStarted {
            provider: SafeText::operator_visible("openai"),
            model: SafeText::operator_visible("openai:gpt-test"),
            operation_fingerprint: OperationFingerprint::from_bytes(label.as_bytes()),
        }
    }

    #[cfg(unix)]
    fn recovery_model_finish(
        sequence: usize,
        cost_usd: Option<f64>,
    ) -> crate::run_lifecycle::RunItemV1 {
        use crate::run_lifecycle::*;
        let cost = cost_usd.map_or(
            crate::runtime::RuntimeCostReport::INCOMPLETE_ZERO,
            |value| {
                crate::runtime::RuntimeCostReport::known(
                    crate::runtime::RuntimeCost::from_usd(value, "recovery test").unwrap(),
                )
            },
        );
        RunItemV1::ModelCallFinished {
            provider: SafeText::operator_visible("openai"),
            model: SafeText::operator_visible("openai:gpt-test"),
            status: RunItemStatus::Completed,
            latency_ms: sequence as u64,
            usage: ModelUsage {
                input_tokens: None,
                output_tokens: None,
            },
            cost,
            error_class: None,
            failure: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_stale_readers_commit_one_digested_interruption() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-concurrent-dead-pid";
        let summary = RunSummary::running(run_id, "scan", None, "target").with_process_id(u32::MAX);
        write_run_summary(tmp.path(), &summary).unwrap();
        let target = std::sync::Arc::new(tmp.path().to_path_buf());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let readers = (0..4)
            .map(|_| {
                let target = std::sync::Arc::clone(&target);
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    load_run_summary(target.as_path(), run_id).unwrap()
                })
            })
            .collect::<Vec<_>>();
        let summaries = readers
            .into_iter()
            .map(|reader| reader.join().unwrap())
            .collect::<Vec<_>>();

        assert!(summaries
            .iter()
            .all(|summary| summary.status == "interrupted"));
        let digest = summaries[0].terminal_result_sha256.as_deref().unwrap();
        assert!(digest.starts_with("sha256:"));
        assert!(summaries
            .iter()
            .all(|summary| summary.terminal_result_sha256.as_deref() == Some(digest)));
        assert_single_recovery_records(tmp.path(), run_id);
    }

    #[cfg(unix)]
    #[test]
    fn recovered_interruption_repairs_missing_derived_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-repair-dead-pid";
        let summary = RunSummary::running(run_id, "scan", None, "target").with_process_id(u32::MAX);
        write_run_summary(tmp.path(), &summary).unwrap();
        let first = load_run_summary(tmp.path(), run_id).unwrap();
        for leaf in ["result.json", "events.jsonl"] {
            fs::remove_file(crate::run_artifacts::run_artifact_path(
                tmp.path(),
                run_id,
                leaf,
            ))
            .unwrap();
        }

        let repaired = load_run_summary(tmp.path(), run_id).unwrap();

        assert_eq!(
            repaired.terminal_result_sha256,
            first.terminal_result_sha256
        );
        assert_single_recovery_records(tmp.path(), run_id);
        let result = read_run_artifact(tmp.path(), run_id, "result.json");
        assert!(result.contains("\"status\": \"interrupted\""), "{result}");
    }

    #[cfg(unix)]
    #[test]
    fn bounded_history_stabilizes_after_interruption_recovery() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-bounded-dead-pid";
        let summary = RunSummary::running(run_id, "scan", None, "target").with_process_id(u32::MAX);
        write_run_summary(tmp.path(), &summary).unwrap();

        let first = list_run_summary_entries_cursor_page(tmp.path(), None, 10).unwrap();
        assert_eq!(first.entries.len(), 1);
        assert!(matches!(
            &first.entries[0].state,
            RunSummaryEntryState::Ready(summary) if summary.status == "interrupted"
        ));
        let recent = list_recent_run_summary_entries(tmp.path(), 10).unwrap();
        assert_eq!(recent.len(), 1);
        let second = list_run_summary_entries_cursor_page(tmp.path(), None, 10).unwrap();

        assert_eq!(second.history.generation, first.history.generation);
        assert_single_recovery_records(tmp.path(), run_id);
    }

    #[cfg(unix)]
    #[test]
    fn recent_history_reports_the_repairing_read_only_once() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-notice-dead-pid";
        let summary = RunSummary::running(run_id, "scan", None, "target").with_process_id(u32::MAX);
        write_run_summary(tmp.path(), &summary).unwrap();

        let first = list_recent_run_summary_entries_with_recoveries(tmp.path(), 10).unwrap();
        let second = list_recent_run_summary_entries_with_recoveries(tmp.path(), 10).unwrap();

        assert_eq!(first.newly_recovered.len(), 1);
        assert_eq!(first.newly_recovered[0].run_id, run_id);
        assert!(first.newly_recovered[0]
            .reason
            .contains("no longer running"));
        assert!(second.newly_recovered.is_empty());
        assert!(matches!(
            &second.entries[0].state,
            RunSummaryEntryState::Ready(summary) if summary.status == "interrupted"
        ));
        assert_single_recovery_records(tmp.path(), run_id);
    }

    #[cfg(unix)]
    #[test]
    fn startup_history_probe_leaves_recovery_for_the_noticing_read() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-startup-probe-dead-pid";
        let summary = RunSummary::running(run_id, "scan", None, "target").with_process_id(u32::MAX);
        write_run_summary(tmp.path(), &summary).unwrap();

        assert!(run_summary_history_exists(tmp.path()).unwrap());
        let planner_read = list_recent_run_summary_entries(tmp.path(), 10).unwrap();
        assert!(matches!(
            &planner_read[0].state,
            RunSummaryEntryState::Ready(summary) if summary.status == "running"
        ));
        let read = list_recent_run_summary_entries_with_recoveries(tmp.path(), 10).unwrap();

        assert_eq!(read.newly_recovered.len(), 1);
        assert_eq!(read.newly_recovered[0].run_id, run_id);
        assert!(matches!(
            &read.entries[0].state,
            RunSummaryEntryState::Ready(summary) if summary.status == "interrupted"
        ));
    }

    #[cfg(unix)]
    fn assert_single_recovery_records(target: &Path, run_id: &str) {
        let events = read_run_artifact(target, run_id, "events.jsonl");
        assert_eq!(events.matches("\"status\":\"interrupted\"").count(), 1);
        let projection = crate::run_lifecycle::load_run_projection(target, run_id)
            .unwrap()
            .projection;
        assert_eq!(
            projection
                .timeline
                .iter()
                .filter(|item| matches!(
                    item.item,
                    crate::run_lifecycle::RunItemV1::TerminalOutcome {
                        status: crate::run_lifecycle::RunItemStatus::Interrupted,
                        ..
                    }
                ))
                .count(),
            1
        );
    }

    #[cfg(unix)]
    fn assert_interrupted_summary(loaded: &[RunSummary]) {
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].status, "interrupted");
        assert!(loaded[0].completed_at_unix.is_some());
        assert!(loaded[0].process_id.is_none());
        assert!(loaded[0]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("no longer running"));
    }

    #[cfg(unix)]
    fn assert_interrupted_run_artifacts(target: &Path, run_id: &str) {
        let failures = crate::run_artifacts::load_run_failures(target, run_id).unwrap();
        assert_eq!(failures.status, "interrupted");
        assert!(failures.failures.is_empty());
        let report = read_run_artifact(target, run_id, "report.md");
        assert!(report.contains("Status: interrupted"));
        let events = read_run_artifact(target, run_id, "events.jsonl");
        assert!(events.contains("\"kind\":\"run\""));
        assert!(events.contains("\"status\":\"interrupted\""));
        let projection = crate::run_lifecycle::load_run_projection(target, run_id)
            .unwrap()
            .projection;
        assert_eq!(
            projection.terminal.map(|terminal| terminal.status),
            Some(crate::run_lifecycle::RunItemStatus::Interrupted)
        );
    }

    #[cfg(unix)]
    fn read_run_artifact(target: &Path, run_id: &str, leaf: &str) -> String {
        fs::read_to_string(crate::run_artifacts::run_artifact_path(
            target, run_id, leaf,
        ))
        .unwrap()
    }

    #[test]
    fn running_summary_with_live_pid_is_left_running() {
        let tmp = tempfile::tempdir().unwrap();
        let summary = RunSummary::running("run-live-pid", "scan", None, "target")
            .with_process_id(std::process::id());
        write_run_summary(tmp.path(), &summary).unwrap();
        let identity = super::super::process_identity::identity_path(tmp.path(), "run-live-pid");
        if cfg!(any(target_os = "linux", target_os = "macos", windows)) {
            assert!(identity.is_file());
        }

        let loaded = list_run_summaries(tmp.path()).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].status, "running");
        assert_eq!(loaded[0].process_id, Some(std::process::id()));
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn live_pid_with_mismatched_birth_token_is_repaired() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-reused-live-pid";
        let summary =
            RunSummary::running(run_id, "scan", None, "target").with_process_id(std::process::id());
        write_run_summary(tmp.path(), &summary).unwrap();
        let path = super::super::process_identity::identity_path(tmp.path(), run_id);
        let mut identity: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        identity["identity"]["startToken"] = serde_json::json!("different-process-birth");
        fs::write(path, serde_json::to_vec(&identity).unwrap()).unwrap();

        let loaded = load_run_summary(tmp.path(), run_id).unwrap();

        assert_eq!(loaded.status, "interrupted");
        assert_eq!(loaded.process_id, None);
        assert!(loaded
            .error
            .unwrap()
            .contains("cannot be verified as the original owner"));
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn legacy_live_pid_without_birth_sidecar_stays_running() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-legacy-live-pid";
        let summary =
            RunSummary::running(run_id, "scan", None, "target").with_process_id(std::process::id());
        write_run_summary(tmp.path(), &summary).unwrap();
        fs::remove_file(super::super::process_identity::identity_path(
            tmp.path(),
            run_id,
        ))
        .unwrap();

        let loaded = load_run_summary(tmp.path(), run_id).unwrap();

        assert_eq!(loaded.status, "running");
        assert_eq!(loaded.process_id, Some(std::process::id()));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn zombie_process_is_repaired_before_it_is_reaped() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-zombie-pid";
        let mut child = std::process::Command::new("sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        wait_until_process_is_not_live(tmp.path(), run_id, child.id());
        let summary =
            RunSummary::running(run_id, "scan", None, "target").with_process_id(child.id());
        write_run_summary(tmp.path(), &summary).unwrap();

        let loaded = load_run_summary(tmp.path(), run_id).unwrap();
        child.wait().unwrap();

        assert_eq!(loaded.status, "interrupted");
        assert!(loaded.error.unwrap().contains("no longer running"));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn wait_until_process_is_not_live(target: &Path, run_id: &str, process_id: u32) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while super::super::process_identity::original_process_is_alive(target, run_id, process_id)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!super::super::process_identity::original_process_is_alive(
            target, run_id, process_id
        ));
    }

    /// Spawn and reap a short-lived child so its pid is known-dead.
    #[cfg(unix)]
    fn spawn_dead_process_id() -> u32 {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn `true`");
        let pid = child.id();
        child.wait().expect("reap child");
        pid
    }
}
