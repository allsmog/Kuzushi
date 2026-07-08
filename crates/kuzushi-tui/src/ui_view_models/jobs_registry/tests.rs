use super::*;
use crate::app::{JobKind, QueuedCommand};
use crate::ActivitySession;
use kuzushi_core::{write_run_summary, RunSummary, V2Config};
use tempfile::TempDir;

fn app_with_target() -> (TempDir, ShellApp) {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    (temp, app)
}

fn persist(app: &ShellApp, summary: RunSummary) {
    write_run_summary(app.target().unwrap(), &summary).unwrap();
}

#[test]
fn jobs_registry_model_projects_recent_disk_runs_newest_first() {
    let (_temp, app) = app_with_target();
    persist(
        &app,
        RunSummary::running("scan-100-a", "scan", Some("sast:scan".into()), "/repo")
            .with_findings(Some(4))
            .complete(),
    );
    persist(
        &app,
        RunSummary::running("scan-200-b", "scan", Some("sast:scan".into()), "/repo").failed("boom"),
    );

    let model = jobs_registry_model(&app, 20);

    assert_eq!(model.live_count, 0);
    assert_eq!(model.rows.len(), 2);
    // list_run_summaries sorts by run_id descending.
    assert_eq!(model.rows[0].run_id, "scan-200-b");
    assert_eq!(model.rows[0].status, JobRunStatus::Failed);
    assert_eq!(model.rows[1].run_id, "scan-100-a");
    assert_eq!(model.rows[1].status, JobRunStatus::Completed);
    assert_eq!(model.rows[1].findings, Some(4));
    assert!(model.rows.iter().all(|row| !row.cancelable));
    assert!(model.rows.iter().all(|row| row.source == JobSource::Disk));
}

#[test]
fn jobs_registry_model_empty_state_reports_runs_root_hint() {
    let (_temp, app) = app_with_target();
    let model = jobs_registry_model(&app, 20);
    assert!(model.rows.is_empty());
    assert_eq!(model.runs_root_hint, ".kuzushi/v3/runs");
}

#[test]
fn jobs_registry_model_live_run_supersedes_its_disk_running_twin() {
    let (_temp, mut app) = app_with_target();
    // On disk the summary is still "running" (the worker has not written
    // completion), and there is a separate finished run.
    persist(
        &app,
        RunSummary::running("tool-500-live", "tool", Some("triage:run".into()), "/repo"),
    );
    persist(
        &app,
        RunSummary::running("tool-100-old", "tool", Some("triage:run".into()), "/repo")
            .with_findings(Some(2))
            .complete(),
    );

    // Bring the same run_id live: a Run slot + an ActivitySession.
    let _ticket = app.jobs_mut().start(JobKind::Run, "triage:run");
    app.set_activity(Some(ActivitySession::new("tool-500-live")));

    let model = jobs_registry_model(&app, 20);

    let live_twin: Vec<&JobRow> = model
        .rows
        .iter()
        .filter(|row| row.run_id == "tool-500-live")
        .collect();
    assert_eq!(live_twin.len(), 1, "run_id must not appear twice");
    assert_eq!(live_twin[0].source, JobSource::Live);
    assert_eq!(live_twin[0].status, JobRunStatus::Running);
    assert!(live_twin[0].cancelable);
    assert_eq!(model.live_count, 1);
    // Live row sorts first; the completed disk run still shows.
    assert_eq!(model.rows[0].run_id, "tool-500-live");
    assert!(model
        .rows
        .iter()
        .any(|row| row.run_id == "tool-100-old" && row.source == JobSource::Disk));
}

#[test]
fn jobs_registry_model_renders_steer_queue_as_pending_rows() {
    let (_temp, mut app) = app_with_target();
    app.steer_queue_mut().enqueue(QueuedCommand {
        raw: "run taint-iris:hunt".into(),
        summary: "run taint-iris:hunt".into(),
    });
    app.steer_queue_mut().enqueue(QueuedCommand {
        raw: "run verify:finding".into(),
        summary: "run verify:finding".into(),
    });

    let model = jobs_registry_model(&app, 20);

    assert_eq!(model.live_count, 2);
    assert_eq!(model.rows[0].run_id, "queued-1");
    assert_eq!(model.rows[0].status, JobRunStatus::Queued);
    assert_eq!(model.rows[0].status.label(), "pending");
    assert!(model.rows[0].cancelable);
    assert_eq!(model.rows[1].run_id, "queued-2");
    assert_eq!(model.rows[1].label, "run verify:finding");
}

#[test]
fn jobs_registry_model_downgrades_orphaned_running_summary() {
    let (_temp, app) = app_with_target();
    // A crashed process leaves a "running" summary tagged with a dead PID.
    persist(
        &app,
        RunSummary::running("scan-900-dead", "scan", Some("sast:scan".into()), "/repo")
            .with_process_id(u32::MAX),
    );

    let model = jobs_registry_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    // On Linux the dead-PID probe downgrades the orphan to `interrupted`.
    // Elsewhere (no /proc) liveness can't be verified, so a disk `running` row
    // with no live twin renders as `Stale` ("running?"), never confident green.
    let expected = if cfg!(target_os = "linux") {
        JobRunStatus::Interrupted
    } else {
        JobRunStatus::Stale
    };
    assert_eq!(model.rows[0].status, expected);
    assert!(!model.rows[0].cancelable);
}

#[test]
fn jobs_registry_model_marks_untwinned_disk_running_row_as_stale() {
    let (_temp, app) = app_with_target();
    // A `running` summary with no process_id (so no repair) and no live twin in
    // this session: liveness is unverifiable, so it must not read as running.
    persist(
        &app,
        RunSummary::running("tool-700-ghost", "tool", Some("triage:run".into()), "/repo"),
    );

    let model = jobs_registry_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].status, JobRunStatus::Stale);
    assert_eq!(model.rows[0].status.label(), "running?");
    assert!(!model.rows[0].cancelable);
}
