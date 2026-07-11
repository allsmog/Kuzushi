use super::scan_status;
use crate::{ScanPanelState, ShellApp, ViewDataState};
use kuzushi_core::run_artifacts::canonical_run_artifact_spec;
use kuzushi_core::{
    RunSummary, RunSummaryEntry, RunSummaryEntryState, RunSummaryIssue, RunTargetGitMetadata,
};

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
    let active = app.scan().map(|scan| active_scan_row(app, scan));
    let active_run_id = active.as_ref().map(|row| row.cells[RUN_ID_CELL].clone());
    let mut rows = active.into_iter().collect::<Vec<_>>();
    rows.extend(past_run_rows(app, past_limit, active_run_id.as_deref()));
    RunTimelineModel { rows }
}

fn past_runs_model(app: &ShellApp) -> Vec<PastRun> {
    let Some(target) = app.target() else {
        return Vec::new();
    };
    let entries = match app
        .workbench_cache()
        .borrow()
        .cached_run_summary_entries(Some(target))
    {
        ViewDataState::Ready(entries) => entries,
        ViewDataState::NotRequested | ViewDataState::Loading => Vec::new(),
    };
    entries.into_iter().map(past_run_from_entry).collect()
}

fn active_scan_row(app: &ShellApp, scan: &ScanPanelState) -> RunTimelineRow {
    RunTimelineRow {
        cells: [
            scan.run_id
                .as_deref()
                .map(short_id)
                .unwrap_or_else(pending_id),
            scan_status(scan),
            active_scan_findings_label(scan),
            active_scan_revision_label(app, scan),
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

fn active_scan_revision_label(app: &ShellApp, scan: &ScanPanelState) -> String {
    match app
        .workbench_cache()
        .borrow()
        .cached_git_metadata(Some(&scan.target))
    {
        ViewDataState::Ready(Some(git)) => target_git_revision_label(&git),
        ViewDataState::Ready(None) | ViewDataState::NotRequested | ViewDataState::Loading => {
            "rev:unknown".to_string()
        }
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

fn past_run_from_entry(entry: RunSummaryEntry) -> PastRun {
    match entry.state {
        RunSummaryEntryState::Ready(summary) => past_run_from_summary(summary),
        RunSummaryEntryState::Issue(issue) => past_run_from_issue(entry.run_id, issue),
    }
}

fn past_run_from_summary(summary: RunSummary) -> PastRun {
    PastRun {
        run_id: summary.run_id,
        status_kind: parse_past_run_status(&summary.status),
        findings: summary.findings,
        revision: summary
            .target_git
            .as_ref()
            .map(target_git_revision_label)
            .unwrap_or_else(|| "rev:unknown".to_string()),
        target: summary.target,
    }
}

fn past_run_from_issue(run_id: String, issue: RunSummaryIssue) -> PastRun {
    let (status_kind, target) = issue_display(issue);
    PastRun {
        run_id,
        status_kind,
        findings: None,
        revision: "rev:unknown".to_string(),
        target,
    }
}

fn issue_display(issue: RunSummaryIssue) -> (PastRunStatus, String) {
    match issue {
        RunSummaryIssue::MissingMetadata => (PastRunStatus::Unknown, String::new()),
        RunSummaryIssue::NonFileMetadata => (
            PastRunStatus::Malformed,
            format!("{} is not a file", run_metadata_artifact_leaf()),
        ),
        RunSummaryIssue::InvalidMetadata(_) => (
            PastRunStatus::Malformed,
            format!("malformed {}", run_metadata_artifact_leaf()),
        ),
        RunSummaryIssue::InvalidRunId(error) => {
            (PastRunStatus::Malformed, format!("invalid run id: {error}"))
        }
        RunSummaryIssue::UnsafeSymlink => (
            PastRunStatus::Malformed,
            "unsafe symlink in run artifacts".to_string(),
        ),
        RunSummaryIssue::NotDirectory => (
            PastRunStatus::Malformed,
            "run path is not a directory".to_string(),
        ),
        RunSummaryIssue::UnreadableMetadata(error) => (
            PastRunStatus::Malformed,
            format!("unreadable metadata: {error}"),
        ),
        RunSummaryIssue::RunIdMismatch { metadata_run_id } => (
            PastRunStatus::Malformed,
            format!("metadata run id mismatch: {metadata_run_id}"),
        ),
    }
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
