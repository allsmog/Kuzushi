use super::ui_runs_root_relative_path;
use crate::app::JobKind;
use crate::{ActivitySession, DagTaskState, RunSummaryEntriesState, ShellApp, ViewDataState};
use kuzushi_core::{RunSummaryEntry, RunSummaryEntryState, RunSummaryIssue};
use std::collections::HashSet;

/// Lifecycle state of a registry row. The registry can only ever show **one**
/// live `Run` at a time (the single-slot `JobHub` reality), so queued steer
/// items render as `Queued`, never `Running` — the signifier must not imply
/// concurrency that does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JobRunStatus {
    Running,
    Canceling,
    WaitingInput,
    Queued,
    /// A disk summary still marked `running` but with **no live backing** in
    /// this session. The liveness can't be trusted (the owning process may
    /// have crashed; the dead-PID probe only exists where `/proc` does), so it
    /// renders muted as `running?` rather than a confident green `running`.
    Stale,
    Completed,
    Failed,
    Canceled,
    Interrupted,
    Partial,
    Skipped,
    Blocked,
    Malformed,
    Unknown,
}

impl JobRunStatus {
    pub(crate) fn label(self) -> &'static str {
        match self {
            JobRunStatus::Running => "running",
            JobRunStatus::Canceling => "canceling",
            JobRunStatus::WaitingInput => "WAITING INPUT",
            JobRunStatus::Queued => "pending",
            JobRunStatus::Stale => "running?",
            JobRunStatus::Completed => "completed",
            JobRunStatus::Failed => "failed",
            JobRunStatus::Canceled => "canceled",
            JobRunStatus::Interrupted => "interrupted",
            JobRunStatus::Partial => "partial",
            JobRunStatus::Skipped => "skipped",
            JobRunStatus::Blocked => "blocked",
            JobRunStatus::Malformed => "malformed",
            JobRunStatus::Unknown => "—",
        }
    }

    /// Status for a **disk** row. A `running` disk summary that survived the
    /// live-supersedes-disk merge has no live twin in this session, so it is
    /// reported as `Stale` (unverifiable liveness), never a confident
    /// `Running`.
    fn from_disk_status(status: &str) -> Self {
        match status.to_ascii_lowercase().as_str() {
            "running" => JobRunStatus::Stale,
            "completed" => JobRunStatus::Completed,
            "failed" => JobRunStatus::Failed,
            "canceled" | "cancelled" => JobRunStatus::Canceled,
            "interrupted" => JobRunStatus::Interrupted,
            "partial" => JobRunStatus::Partial,
            "skipped" => JobRunStatus::Skipped,
            "blocked" => JobRunStatus::Blocked,
            _ => JobRunStatus::Unknown,
        }
    }
}

/// Whether a row was reconciled from live app state or read off disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JobSource {
    Live,
    Disk,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JobRow {
    pub(crate) run_id: String,
    pub(crate) kind: String,
    pub(crate) label: String,
    pub(crate) status: JobRunStatus,
    pub(crate) elapsed_secs: Option<u64>,
    pub(crate) phase: Option<String>,
    pub(crate) findings: Option<u64>,
    pub(crate) target: String,
    pub(crate) source: JobSource,
    /// True only for rows a `jobs -k` can act on: the live Run/Agent/Plan/
    /// Threat slots and queued steer items. Completed disk rows are inert.
    pub(crate) cancelable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JobsRegistryModel {
    pub(crate) rows: Vec<JobRow>,
    pub(crate) live_count: usize,
    pub(crate) history_state: JobHistoryState,
    pub(crate) runs_root_hint: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JobHistoryState {
    NoTarget,
    NotRequested,
    Loading,
    Ready,
    Failed(String),
}

/// Pure projection over live state and the asynchronously hydrated run-history
/// page. Live rows come first (Running, then Queued), then recent disk rows
/// de-duped by `run_id` so a live run's still-`running` disk twin never appears
/// twice. This function never reads or repairs run artifacts.
pub(crate) fn jobs_registry_model(app: &ShellApp, disk_limit: usize) -> JobsRegistryModel {
    let live = live_job_rows(app);
    let live_ids: HashSet<String> = live.iter().map(|row| row.run_id.clone()).collect();
    let live_count = live.len();
    let (disk_rows, history_state) = hydrated_disk_job_rows(app, disk_limit);

    let mut rows = live;
    rows.extend(
        disk_rows
            .into_iter()
            .filter(|row| !live_ids.contains(&row.run_id)),
    );

    JobsRegistryModel {
        rows,
        live_count,
        history_state,
        runs_root_hint: ui_runs_root_relative_path(),
    }
}

/// Live rows reconciled from app state: the one live `Run` (from the shared
/// `JobHub` slot + its `ActivitySession`), then any live planner/threat/agent
/// worker, then the operator steer queue as `Queued` rows.
fn live_job_rows(app: &ShellApp) -> Vec<JobRow> {
    let mut rows = Vec::new();
    if let Some(row) = live_run_row(app) {
        rows.push(row);
    }
    rows.extend(worker_job_rows(app));
    rows.extend(queued_job_rows(app));
    rows
}

fn live_run_row(app: &ShellApp) -> Option<JobRow> {
    if !app.jobs().is_running(JobKind::Run) {
        return None;
    }
    let session = app.activity()?;
    let scan = app.scan().filter(|scan| scan.running);
    let label = app
        .running_tool_name_owned()
        .unwrap_or_else(|| "scan".to_string());
    Some(JobRow {
        run_id: session.run_id.clone(),
        kind: kind_from_run_id(&session.run_id),
        label,
        status: live_run_status(app, session, scan),
        elapsed_secs: Some(session.started_at.elapsed().as_secs()),
        phase: live_run_phase(session, scan.map(|scan| scan.stage.as_str())),
        findings: scan.map(|scan| scan.findings_count as u64),
        target: target_label(app),
        source: JobSource::Live,
        cancelable: true,
    })
}

fn live_run_status(
    app: &ShellApp,
    session: &ActivitySession,
    scan: Option<&crate::ScanPanelState>,
) -> JobRunStatus {
    let activity_is_canceling = session
        .tasks
        .values()
        .any(|row| row.state == DagTaskState::Canceling);
    if activity_is_canceling
        || app.tool_abort_requested()
        || scan.is_some_and(|scan| scan.abort_requested)
    {
        JobRunStatus::Canceling
    } else {
        JobRunStatus::Running
    }
}

/// Current step of the live run: the active DAG row's label, falling back to
/// the scan stage. Labelled "current step" in the UI — it can lag reality, so
/// it never claims completion the walker hasn't reconciled.
fn live_run_phase(session: &ActivitySession, scan_stage: Option<&str>) -> Option<String> {
    let active = session
        .tasks
        .values()
        .find(|row| row.state == DagTaskState::Active)
        .map(|row| {
            if row.last_label.is_empty() {
                row.task_id.clone()
            } else {
                row.last_label.clone()
            }
        });
    active.or_else(|| {
        scan_stage
            .map(str::to_string)
            .filter(|stage| !stage.is_empty())
    })
}

fn worker_job_rows(app: &ShellApp) -> Vec<JobRow> {
    let mut rows = Vec::new();
    if app.jobs().is_running(JobKind::Plan) && app.planner_running() {
        rows.push(worker_job_row(
            "plan",
            "planner",
            requested_status(app.plan_abort_requested()),
            None,
        ));
    }
    if app.jobs().is_running(JobKind::Threat) && app.threat_worker_running() {
        rows.push(worker_job_row(
            "threat",
            "threat-model",
            requested_status(app.threat_abort_requested()),
            None,
        ));
    }
    if let Some(agent) = agent_worker_job_row(app) {
        rows.push(agent);
    }
    rows
}

fn agent_worker_job_row(app: &ShellApp) -> Option<JobRow> {
    if !app.jobs().is_running(JobKind::Agent) {
        return None;
    }
    let question = (!app.active_agent_is_auxiliary_read_only())
        .then(|| {
            app.activity()
                .and_then(|session| session.operator_question.as_ref())
        })
        .flatten();
    let status = if app.jobs().cancel_requested(JobKind::Agent)
        || app.agent_chat().is_some_and(|agent| agent.abort_requested)
    {
        JobRunStatus::Canceling
    } else {
        question.map_or(JobRunStatus::Running, |_| JobRunStatus::WaitingInput)
    };
    let phase = question.map(|card| {
        format!(
            "question {}/{}",
            card.active_question_index() + 1,
            card.request().questions.len()
        )
    });
    let run_id = app.active_agent_run_id().unwrap_or("agent");
    Some(worker_job_row(&run_id, "agent", status, phase))
}

fn requested_status(abort_requested: bool) -> JobRunStatus {
    if abort_requested {
        JobRunStatus::Canceling
    } else {
        JobRunStatus::Running
    }
}

fn worker_job_row(
    run_id: &str,
    label: &str,
    status: JobRunStatus,
    phase: Option<String>,
) -> JobRow {
    JobRow {
        run_id: run_id.to_string(),
        kind: run_id.to_string(),
        label: label.to_string(),
        status,
        elapsed_secs: None,
        phase,
        findings: None,
        target: String::new(),
        source: JobSource::Live,
        cancelable: true,
    }
}

fn queued_job_rows(app: &ShellApp) -> Vec<JobRow> {
    app.steer_queue()
        .iter()
        .map(|(run_id, cmd)| JobRow {
            run_id,
            kind: "queued".to_string(),
            label: cmd.summary.clone(),
            status: JobRunStatus::Queued,
            elapsed_secs: None,
            phase: None,
            findings: None,
            target: target_label(app),
            source: JobSource::Live,
            cancelable: true,
        })
        .collect()
}

fn hydrated_disk_job_rows(app: &ShellApp, disk_limit: usize) -> (Vec<JobRow>, JobHistoryState) {
    let Some(target) = app.target() else {
        return (Vec::new(), JobHistoryState::NoTarget);
    };
    match app
        .workbench_cache()
        .borrow()
        .cached_run_summary_entries(Some(target))
    {
        ViewDataState::Ready(RunSummaryEntriesState::Ready(entries)) => {
            (disk_job_rows(entries, disk_limit), JobHistoryState::Ready)
        }
        ViewDataState::Ready(RunSummaryEntriesState::Failed(error)) => {
            (Vec::new(), JobHistoryState::Failed(error))
        }
        ViewDataState::Loading => (Vec::new(), JobHistoryState::Loading),
        ViewDataState::NotRequested => (Vec::new(), JobHistoryState::NotRequested),
    }
}

fn disk_job_rows(entries: Vec<RunSummaryEntry>, disk_limit: usize) -> Vec<JobRow> {
    entries
        .into_iter()
        .take(disk_limit)
        .map(disk_job_row_from_entry)
        .collect()
}

fn disk_job_row_from_entry(entry: RunSummaryEntry) -> JobRow {
    let RunSummaryEntry {
        run_id,
        path,
        state,
    } = entry;
    match state {
        RunSummaryEntryState::Ready(summary) => disk_summary_job_row(summary),
        RunSummaryEntryState::Issue(issue) => disk_issue_job_row(run_id, path, issue),
    }
}

fn disk_issue_job_row(run_id: String, path: std::path::PathBuf, issue: RunSummaryIssue) -> JobRow {
    JobRow {
        run_id,
        kind: "history".to_string(),
        label: format!("run history issue: {issue:?}"),
        status: JobRunStatus::Malformed,
        elapsed_secs: None,
        phase: None,
        findings: None,
        target: path.display().to_string(),
        source: JobSource::Disk,
        cancelable: false,
    }
}

fn disk_summary_job_row(summary: kuzushi_core::RunSummary) -> JobRow {
    let elapsed_secs = summary
        .completed_at_unix
        .map(|completed| completed.saturating_sub(summary.started_at_unix));
    JobRow {
        run_id: summary.run_id.clone(),
        kind: if summary.kind.is_empty() {
            kind_from_run_id(&summary.run_id)
        } else {
            summary.kind.clone()
        },
        label: summary.tool.clone().unwrap_or_else(|| summary.kind.clone()),
        status: JobRunStatus::from_disk_status(&summary.status),
        elapsed_secs,
        phase: None,
        findings: summary.findings,
        target: summary.target.clone(),
        source: JobSource::Disk,
        cancelable: false,
    }
}

fn kind_from_run_id(run_id: &str) -> String {
    run_id
        .split('-')
        .next()
        .filter(|prefix| !prefix.is_empty())
        .unwrap_or("run")
        .to_string()
}

fn target_label(app: &ShellApp) -> String {
    app.target()
        .map(|path| path.display().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
