use super::scan_status;
use crate::{ScanPanelState, ShellApp};
use std::path::{Path, PathBuf};

const RUN_TIMELINE_COLUMN_COUNT: usize = 4;
const RUN_ID_CELL: usize = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PastRunStatus {
    Complete,
    Running,
    Partial,
    Paused,
    Failed,
    Unknown,
}

#[derive(Debug, Clone)]
struct PastRun {
    run_id: String,
    status_kind: PastRunStatus,
    findings: Option<u64>,
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
            PastRunStatus::Failed => "failed",
            PastRunStatus::Unknown => "—",
        }
    }
}

pub(crate) fn run_timeline_model(app: &ShellApp, past_limit: usize) -> RunTimelineModel {
    let active = app.scan.as_ref().map(active_scan_row);
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
            scan.findings_count.to_string(),
            scan.target.display().to_string(),
        ],
        tone: active_scan_status(scan),
    }
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
            past.target.clone(),
        ],
        tone: past.status_kind,
    }
}

fn short_id(run_id: &str) -> String {
    run_id.chars().take(8).collect()
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
    app.target
        .as_deref()
        .map(|target| target.join(".kuzushi/runs"))
        .unwrap_or_else(|| PathBuf::from(".kuzushi/runs"))
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
    let (status_kind, findings, target) = read_past_run_metadata(&entry.path());
    Some(PastRun {
        run_id,
        status_kind,
        findings,
        target,
    })
}

fn read_past_run_metadata(run_dir: &Path) -> (PastRunStatus, Option<u64>, String) {
    let value = read_run_artifact_json(&run_dir.join("run.json"))
        .or_else(|| read_run_artifact_json(&run_dir.join("summary.json")));
    let Some(value) = value else {
        return empty_past_run_metadata();
    };
    (
        value
            .get("status")
            .and_then(serde_json::Value::as_str)
            .map(parse_past_run_status)
            .unwrap_or(PastRunStatus::Unknown),
        value.get("findings").and_then(serde_json::Value::as_u64),
        value
            .get("target")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_default(),
    )
}

fn read_run_artifact_json(path: &Path) -> Option<serde_json::Value> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice::<serde_json::Value>(&bytes).ok()
}

fn empty_past_run_metadata() -> (PastRunStatus, Option<u64>, String) {
    (PastRunStatus::Unknown, None, String::new())
}

fn parse_past_run_status(status: &str) -> PastRunStatus {
    match status.to_ascii_lowercase().as_str() {
        "completed" | "complete" | "done" | "ok" | "success" => PastRunStatus::Complete,
        "running" | "started" => PastRunStatus::Running,
        "partial" => PastRunStatus::Partial,
        "paused" => PastRunStatus::Paused,
        "failed" | "error" => PastRunStatus::Failed,
        _ => PastRunStatus::Unknown,
    }
}

#[cfg(test)]
mod tests;
