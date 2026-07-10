use super::{scan_status, ui_runs_root};
use crate::{ScanPanelState, ShellApp};
use kuzushi_core::run_artifacts::canonical_run_artifact_spec;
use kuzushi_core::RunTargetGitMetadata;
use std::path::{Path, PathBuf};

const RUN_TIMELINE_COLUMN_COUNT: usize = 5;
const RUN_ID_CELL: usize = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PastRunStatus {
    Complete,
    Running,
    Partial,
    Paused,
    Interrupted,
    Skipped,
    Failed,
    Canceled,
    Malformed,
    Unknown,
}

#[derive(Debug, Clone)]
struct PastRun {
    run_id: String,
    status_kind: PastRunStatus,
    findings: Option<u64>,
    revision: String,
    target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunTimelineModel {
    pub(crate) rows: Vec<RunTimelineRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunTimelineRow {
    pub(crate) cells: [String; RUN_TIMELINE_COLUMN_COUNT],
    pub(crate) tone: PastRunStatus,
}

impl PastRun {
    pub(crate) fn status_label(&self) -> &'static str {
        match self.status_kind {
            PastRunStatus::Complete => "completed",
            PastRunStatus::Running => "running",
            PastRunStatus::Partial => "partial",
            PastRunStatus::Paused => "paused",
            PastRunStatus::Interrupted => "interrupted",
            PastRunStatus::Skipped => "skipped",
            PastRunStatus::Failed => "failed",
            PastRunStatus::Canceled => "canceled",
            PastRunStatus::Malformed => "malformed",
            PastRunStatus::Unknown => "—",
        }
    }
}

pub(crate) fn run_timeline_model(app: &ShellApp, past_limit: usize) -> RunTimelineModel {
    let active = app.scan().map(active_scan_row);
    let active_run_id = active.as_ref().map(|row| row.cells[RUN_ID_CELL].clone());
    let mut rows = active.into_iter().collect::<Vec<_>>();
    rows.extend(past_run_rows(app, past_limit, active_run_id.as_deref()));
    RunTimelineModel { rows }
}

fn past_runs_model(app: &ShellApp) -> Vec<PastRun> {
    collect_past_runs(&runs_root(app))
}

fn active_scan_row(scan: &ScanPanelState) -> RunTimelineRow {
    RunTimelineRow {
        cells: [
            scan.run_id
                .as_deref()
                .map(short_id)
                .unwrap_or_else(pending_id),
            scan_status(scan),
            active_scan_findings_label(scan),
            active_scan_revision_label(scan),
            scan.target.display().to_string(),
        ],
        tone: active_scan_status(scan),
    }
}

fn active_scan_findings_label(scan: &ScanPanelState) -> String {
    if scan.running && scan.findings_count == 0 {
        "—".to_string()
    } else {
        scan.findings_count.to_string()
    }
}

fn active_scan_revision_label(scan: &ScanPanelState) -> String {
    kuzushi_core::workspace::target_git_metadata(&scan.target)
        .map(|git| target_git_revision_label(&git))
        .unwrap_or_else(|| "rev:unknown".to_string())
}

fn active_scan_status(scan: &ScanPanelState) -> PastRunStatus {
    if scan.error.is_some() {
        PastRunStatus::Failed
    } else if scan.running {
        PastRunStatus::Running
    } else {
        PastRunStatus::Complete
    }
}

fn past_run_rows(
    app: &ShellApp,
    past_limit: usize,
    active_run_id: Option<&str>,
) -> Vec<RunTimelineRow> {
    let mut past_runs = past_runs_model(app);
    past_runs.sort_by(|a, b| b.run_id.cmp(&a.run_id));
    past_runs
        .iter()
        .take(past_limit)
        .map(past_run_row)
        .filter(|row| Some(row.cells[RUN_ID_CELL].as_str()) != active_run_id)
        .collect()
}

fn past_run_row(past: &PastRun) -> RunTimelineRow {
    RunTimelineRow {
        cells: [
            short_id(&past.run_id),
            past.status_label().to_string(),
            finding_count_label(past.findings),
            past.revision.clone(),
            past.target.clone(),
        ],
        tone: past.status_kind,
    }
}

fn short_id(run_id: &str) -> String {
    let chars: Vec<char> = run_id.chars().collect();
    if chars.len() <= 16 {
        return run_id.to_string();
    }
    let head: String = chars.iter().take(6).collect();
    let tail: String = chars.iter().skip(chars.len() - 6).collect();
    format!("{head}…{tail}")
}

fn pending_id() -> String {
    "pending".to_string()
}

fn finding_count_label(findings: Option<u64>) -> String {
    findings
        .map(|count| count.to_string())
        .unwrap_or_else(|| "\u{2014}".to_string())
}

fn runs_root(app: &ShellApp) -> PathBuf {
    ui_runs_root(app.target())
}

fn collect_past_runs(runs_root: &Path) -> Vec<PastRun> {
    let Ok(entries) = std::fs::read_dir(runs_root) else {
        return Vec::new();
    };
    entries.flatten().filter_map(past_run_from_entry).collect()
}

fn past_run_from_entry(entry: std::fs::DirEntry) -> Option<PastRun> {
    if !entry.metadata().ok()?.is_dir() {
        return None;
    }
    let run_id = entry.file_name().to_string_lossy().to_string();
    let (status_kind, findings, revision, target) = read_past_run_metadata(&entry.path());
    Some(PastRun {
        run_id,
        status_kind,
        findings,
        revision,
        target,
    })
}

fn read_past_run_metadata(run_dir: &Path) -> (PastRunStatus, Option<u64>, String, String) {
    let metadata_leaf = run_metadata_artifact_leaf();
    match read_run_artifact_json(&run_dir.join(metadata_leaf)) {
        JsonArtifactRead::Present(value) => past_run_metadata_from_value(&value),
        JsonArtifactRead::Malformed => return malformed_past_run_metadata(metadata_leaf),
        JsonArtifactRead::NonFile => return non_file_past_run_metadata(metadata_leaf),
        JsonArtifactRead::Missing => empty_past_run_metadata(),
    }
}

fn past_run_metadata_from_value(
    value: &serde_json::Value,
) -> (PastRunStatus, Option<u64>, String, String) {
    (
        value
            .get("status")
            .and_then(serde_json::Value::as_str)
            .map(parse_past_run_status)
            .unwrap_or(PastRunStatus::Unknown),
        value.get("findings").and_then(serde_json::Value::as_u64),
        run_revision_label(&value),
        value
            .get("target")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_default(),
    )
}

fn run_revision_label(value: &serde_json::Value) -> String {
    value
        .get("targetGit")
        .or_else(|| value.get("target_git"))
        .and_then(|git| serde_json::from_value::<RunTargetGitMetadata>(git.clone()).ok())
        .map(|git| target_git_revision_label(&git))
        .unwrap_or_else(|| "rev:unknown".to_string())
}

fn target_git_revision_label(git: &RunTargetGitMetadata) -> String {
    let short = git.sha.chars().take(7).collect::<String>();
    let dirty = if git.dirty { "*" } else { "" };
    if short.is_empty() {
        "rev:unknown".to_string()
    } else {
        format!("rev:{short}{dirty}")
    }
}

fn run_metadata_artifact_leaf() -> &'static str {
    canonical_run_artifact_spec("run.json")
        .expect("run metadata artifact must be in shared canonical spec")
        .leaf
}

enum JsonArtifactRead {
    Present(serde_json::Value),
    Malformed,
    NonFile,
    Missing,
}

fn read_run_artifact_json(path: &Path) -> JsonArtifactRead {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return JsonArtifactRead::NonFile,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return JsonArtifactRead::Missing;
        }
        Err(_) => return JsonArtifactRead::Malformed,
    }
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return JsonArtifactRead::Malformed,
    };
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(value) if value.is_object() => JsonArtifactRead::Present(value),
        Ok(_) => JsonArtifactRead::Malformed,
        Err(_) => JsonArtifactRead::Malformed,
    }
}

fn empty_past_run_metadata() -> (PastRunStatus, Option<u64>, String, String) {
    (
        PastRunStatus::Unknown,
        None,
        "rev:unknown".to_string(),
        String::new(),
    )
}

fn malformed_past_run_metadata(file: &str) -> (PastRunStatus, Option<u64>, String, String) {
    (
        PastRunStatus::Malformed,
        None,
        "rev:unknown".to_string(),
        format!("malformed {file}"),
    )
}

fn non_file_past_run_metadata(file: &str) -> (PastRunStatus, Option<u64>, String, String) {
    (
        PastRunStatus::Malformed,
        None,
        "rev:unknown".to_string(),
        format!("{file} is not a file"),
    )
}

fn parse_past_run_status(status: &str) -> PastRunStatus {
    match status.to_ascii_lowercase().as_str() {
        "completed" => PastRunStatus::Complete,
        "running" => PastRunStatus::Running,
        "partial" => PastRunStatus::Partial,
        "paused" => PastRunStatus::Paused,
        "failed" => PastRunStatus::Failed,
        "canceled" | "cancelled" => PastRunStatus::Canceled,
        "interrupted" => PastRunStatus::Interrupted,
        "skipped" => PastRunStatus::Skipped,
        _ => PastRunStatus::Unknown,
    }
}

#[cfg(test)]
mod tests;
