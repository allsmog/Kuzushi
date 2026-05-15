use crate::ShellApp;
use std::path::{Path, PathBuf};

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
pub(crate) struct PastRun {
    pub(crate) run_id: String,
    pub(crate) status_kind: PastRunStatus,
    pub(crate) findings: Option<u64>,
    pub(crate) target: String,
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

pub(crate) fn past_runs_model(app: &ShellApp) -> Vec<PastRun> {
    collect_past_runs(&runs_root(app))
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
