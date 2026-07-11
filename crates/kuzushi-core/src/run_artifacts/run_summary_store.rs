use super::canonical_run_files::ensure_canonical_run_files;
use super::run_reproducibility_metadata::{
    summary_with_dynamic_metadata, summary_with_trace_metadata,
};
use super::{
    checked_latest_run_path, checked_run_artifact_path, checked_runs_root, now_unix, RunSummary,
};
use crate::artifact_contract::{canonical_run_artifact_spec, CanonicalRunArtifactSpec};
use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_LATEST_RUN_POINTER_BYTES: usize = 256;

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

#[derive(Debug, Clone, PartialEq, Eq)]
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
    let (summary_path, summary) = write_run_summary_snapshot(target, summary)?;
    ensure_canonical_run_files(target, &summary.run_id, &summary.status)?;
    write_latest_run_id(target, &summary)?;
    Ok(summary_path)
}

fn write_run_summary_snapshot(
    target: &Path,
    summary: &RunSummary,
) -> Result<(PathBuf, RunSummary)> {
    let _guard = super::run_ledger::acquire_run_ledger_lock(target, &summary.run_id)?;
    let metadata_path =
        checked_run_artifact_path(target, &summary.run_id, run_metadata_artifact_spec().leaf)?;
    let summary = summary_for_write(target, &metadata_path, summary);
    let summary_path = write_run_summary_file(&metadata_path, &summary)?;
    Ok((summary_path, summary))
}

fn summary_for_write(target: &Path, path: &Path, summary: &RunSummary) -> RunSummary {
    let Some(existing) = read_run_summary_file(target, &summary.run_id, path) else {
        return summary_with_dynamic_metadata(target, summary);
    };
    let mut next = summary.clone();
    next.started_at_unix = existing.started_at_unix;
    next = next.with_reproducibility_from(&existing);
    summary_with_trace_metadata(target, &next)
}

pub fn load_run_summary(target: impl AsRef<Path>, run_id: &str) -> Result<RunSummary> {
    let target = target.as_ref();
    let (path, body) = super::run_artifact_reader::read_run_artifact_text_required(
        target,
        run_id,
        run_metadata_artifact_spec().leaf,
        "Run metadata",
    )?;
    let summary = parse_run_summary_body(&body, &path)?;
    if summary.run_id != run_id {
        anyhow::bail!(
            "Run metadata runId {:?} does not match requested run id {run_id:?}: {}",
            summary.run_id,
            path.display()
        );
    }
    Ok(repair_stale_running_summary(target, &path, summary))
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
            return Ok(LatestRunPointerState::Missing)
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
            ))
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
    let target = target.as_ref();
    let root = checked_runs_root(target)?;
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(&root).with_context(|| format!("Could not read {}", root.display()))?
    {
        let entry = entry?;
        entries.push(read_run_summary_entry(target, &entry));
    }
    entries.sort_by(compare_run_summary_entries);
    Ok(entries)
}

fn read_run_summary_entry(target: &Path, entry: &fs::DirEntry) -> RunSummaryEntry {
    let run_id = entry.file_name().to_string_lossy().into_owned();
    let path = entry.path();
    let state = run_summary_entry_state(target, entry, &run_id);
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
) -> RunSummaryEntryState {
    if let Err(error) = super::RunId::parse(run_id) {
        return RunSummaryEntryState::Issue(RunSummaryIssue::InvalidRunId(error.to_string()));
    }
    match entry.file_type() {
        Ok(kind) if kind.is_symlink() => issue(RunSummaryIssue::UnsafeSymlink),
        Ok(kind) if !kind.is_dir() => issue(RunSummaryIssue::NotDirectory),
        Ok(_) => read_run_metadata_entry(target, &entry.path(), run_id),
        Err(error) => issue(RunSummaryIssue::UnreadableMetadata(error.to_string())),
    }
}

fn read_run_metadata_entry(target: &Path, dir: &Path, run_id: &str) -> RunSummaryEntryState {
    let path = dir.join(run_metadata_artifact_spec().leaf);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            issue(RunSummaryIssue::MissingMetadata)
        }
        Err(error) => issue(RunSummaryIssue::UnreadableMetadata(error.to_string())),
        Ok(metadata) if metadata.file_type().is_symlink() => issue(RunSummaryIssue::UnsafeSymlink),
        Ok(metadata) if !metadata.is_file() => issue(RunSummaryIssue::NonFileMetadata),
        Ok(_) => parse_run_summary_entry(target, &path, run_id),
    }
}

fn parse_run_summary_entry(target: &Path, path: &Path, run_id: &str) -> RunSummaryEntryState {
    let read = super::read_run_artifact_text(target, run_id, run_metadata_artifact_spec().leaf);
    let body = match read.require("Run metadata") {
        Ok((_, body)) => body,
        Err(error) => return issue(RunSummaryIssue::UnreadableMetadata(error.to_string())),
    };
    let summary = match parse_run_summary_body(&body, path) {
        Ok(summary) => summary,
        Err(error) => return issue(RunSummaryIssue::InvalidMetadata(error.to_string())),
    };
    if summary.run_id != run_id {
        return issue(RunSummaryIssue::RunIdMismatch {
            metadata_run_id: summary.run_id,
        });
    }
    RunSummaryEntryState::Ready(repair_stale_running_summary(target, path, summary))
}

fn issue(value: RunSummaryIssue) -> RunSummaryEntryState {
    RunSummaryEntryState::Issue(value)
}

fn compare_run_summary_entries(
    left: &RunSummaryEntry,
    right: &RunSummaryEntry,
) -> std::cmp::Ordering {
    match (&left.state, &right.state) {
        (RunSummaryEntryState::Ready(left), RunSummaryEntryState::Ready(right)) => right
            .started_at_unix
            .cmp(&left.started_at_unix)
            .then_with(|| right.run_id.cmp(&left.run_id)),
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
    parse_run_summary_body(&value, &path).ok()
}

fn parse_run_summary_body(body: &str, path: &Path) -> Result<RunSummary> {
    let value: Value = serde_json::from_str(body)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    if !value.is_object() {
        anyhow::bail!("Run metadata is not a JSON object: {}", path.display());
    }
    serde_json::from_value(value).map_err(|error| {
        anyhow::anyhow!("Run metadata is not canonical: {error}: {}", path.display())
    })
}

fn run_metadata_artifact_spec() -> &'static CanonicalRunArtifactSpec {
    canonical_run_artifact_spec("run.json").expect("run metadata artifact must be in shared spec")
}

fn write_run_summary_file(path: &Path, summary: &RunSummary) -> Result<PathBuf> {
    reject_non_file_target(path, "Run metadata target")?;
    let body = format!("{}\n", serde_json::to_string_pretty(summary)?);
    crate::fs_atomic::write_atomic(path, &body)
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path.to_path_buf())
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
    (candidate.started_at_unix, &candidate.run_id) > (current.started_at_unix, &current.run_id)
}

pub fn repair_latest_run_pointer(target: impl AsRef<Path>) -> Result<Option<String>> {
    let target = target.as_ref();
    let _guard = super::run_ledger::acquire_latest_pointer_lock(target)?;
    let latest_path = checked_latest_run_path(target)?;
    let Some(newest) = list_run_summaries(target)?.into_iter().next() else {
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
    summaries.sort_by(|left, right| {
        right
            .started_at_unix
            .cmp(&left.started_at_unix)
            .then_with(|| right.run_id.cmp(&left.run_id))
    });
}

fn repair_stale_running_summary(
    target: &Path,
    summary_path: &Path,
    summary: RunSummary,
) -> RunSummary {
    let Some(process_id) = summary.process_id else {
        return summary;
    };
    if summary.status != "running" || process_is_alive(process_id) {
        return summary;
    }
    let repaired = interrupted_summary(summary, process_id);
    persist_interrupted_repair(target, summary_path, &repaired);
    repaired
}

fn persist_interrupted_repair(target: &Path, summary_path: &Path, repaired: &RunSummary) {
    let Ok(body) = serde_json::to_string_pretty(repaired) else {
        return;
    };
    if crate::fs_atomic::write_atomic(summary_path, &format!("{body}\n")).is_err() {
        return;
    }
    let _ = ensure_canonical_run_files(target, &repaired.run_id, "interrupted");
    let event = super::RunEvent::new(
        0,
        "run",
        "interrupted",
        repaired
            .error
            .clone()
            .unwrap_or_else(|| "run interrupted".to_string()),
    );
    let _ = super::append_run_event(target, &repaired.run_id, &event);
    let trace = super::RunTraceStep::new(0, "refused", "run interrupted during recovery")
        .with_severity("danger");
    let _ = super::append_run_trace_step_with_next_number(target, &repaired.run_id, &trace);
}

fn interrupted_summary(mut summary: RunSummary, process_id: u32) -> RunSummary {
    summary.status = "interrupted".to_string();
    summary.completed_at_unix = Some(now_unix());
    summary.error = Some(format!(
        "run process {process_id} is no longer running; marking summary interrupted"
    ));
    summary.process_id = None;
    summary
}

#[cfg(target_os = "linux")]
fn process_is_alive(process_id: u32) -> bool {
    let proc_root = Path::new("/proc");
    if !proc_root.exists() {
        return true;
    }
    proc_root.join(process_id.to_string()).exists()
}

/// `kill(pid, 0)` probes process existence without delivering a signal:
/// `0` means alive, `EPERM` means alive but owned by another user, and
/// `ESRCH` (or any other error) means no such process.
#[cfg(all(unix, not(target_os = "linux")))]
fn process_is_alive(process_id: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(process_id) else {
        // A pid that cannot be represented on this platform can never
        // name a live process (and would alias `kill(-1, 0)` if cast).
        return false;
    };
    if pid <= 0 {
        return false;
    }
    let probe = unsafe { libc::kill(pid, 0) };
    probe == 0 || last_errno_is_eperm()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn last_errno_is_eperm() -> bool {
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// No portable liveness probe exists here; claiming "dead" would fabricate
/// an interrupted state, so the summary is left untouched.
#[cfg(not(unix))]
fn process_is_alive(_process_id: u32) -> bool {
    true
}

#[cfg(test)]
mod liveness_tests {
    use super::*;

    #[test]
    fn current_process_is_alive() {
        assert!(process_is_alive(std::process::id()));
    }

    #[cfg(unix)]
    #[test]
    fn reaped_child_process_is_not_alive() {
        assert!(!process_is_alive(spawn_dead_process_id()));
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
        let trace = read_run_artifact(target, run_id, "trace.jsonl");
        assert!(trace.contains("\"kind\":\"refused\""));
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

        let loaded = list_run_summaries(tmp.path()).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].status, "running");
        assert_eq!(loaded[0].process_id, Some(std::process::id()));
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
