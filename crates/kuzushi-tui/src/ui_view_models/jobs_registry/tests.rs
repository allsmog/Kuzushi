use super::*;
use crate::app::{JobKind, QueuedCommand, ViewHydrationKey};
use crate::ui_view_models::activity_header::activity_header_model;
use crate::{ActivityRouteState, ActivitySession};
use kuzushi_core::{
    write_run_summary, RunSummary, RunSummaryEntry, RunSummaryEntryState, RunSummaryIssue, V2Config,
};
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

fn hydrate_run_history(app: &mut ShellApp) {
    let target = app.target().unwrap().to_path_buf();
    app.hydrate_view_keys_blocking(&target, vec![ViewHydrationKey::RunSummaryEntries]);
}

#[test]
fn jobs_registry_model_projects_recent_disk_runs_newest_first() {
    let (_temp, mut app) = app_with_target();
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
    hydrate_run_history(&mut app);

    let model = jobs_registry_model(&app, 20);

    assert_eq!(model.live_count, 0);
    assert_eq!(model.history_state, JobHistoryState::Ready);
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
fn jobs_registry_model_preserves_blocked_disk_status_and_label() {
    let (_temp, mut app) = app_with_target();
    persist(
        &app,
        RunSummary::running(
            "tool-300-blocked",
            "tool",
            Some("sast:scan".into()),
            "/repo",
        )
        .blocked("autonomy posture refused the tool"),
    );
    hydrate_run_history(&mut app);

    let model = jobs_registry_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].status, JobRunStatus::Blocked);
    assert_eq!(model.rows[0].status.label(), "blocked");
}

#[test]
fn jobs_registry_model_empty_state_reports_runs_root_hint() {
    let (_temp, mut app) = app_with_target();
    hydrate_run_history(&mut app);
    let model = jobs_registry_model(&app, 20);
    assert!(model.rows.is_empty());
    assert_eq!(model.history_state, JobHistoryState::Ready);
    assert_eq!(model.runs_root_hint, ".kuzushi/v3/runs");
}

#[test]
fn jobs_registry_model_surfaces_malformed_run_history_entries() {
    let (_temp, app) = app_with_target();
    let target = app.target().unwrap().to_path_buf();
    let key = ViewHydrationKey::RunSummaryEntries;
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(crate::app::ViewHydrationResult {
            target: target.clone(),
            key,
            value: crate::app::ViewHydrationValue::RunSummaryEntries(
                crate::app::RunSummaryEntriesHydration::without_recoveries(
                    crate::app::RunSummaryEntriesState::Ready(vec![RunSummaryEntry {
                        run_id: "run-malformed".to_string(),
                        path: target.join(".kuzushi/v3/runs/run-malformed"),
                        state: RunSummaryEntryState::Issue(RunSummaryIssue::InvalidMetadata(
                            "expected value".to_string(),
                        )),
                    }]),
                ),
            ),
        });

    let model = jobs_registry_model(&app, 20);

    assert_eq!(model.history_state, JobHistoryState::Ready);
    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].status, JobRunStatus::Malformed);
    assert!(model.rows[0].label.contains("InvalidMetadata"));
    assert!(!model.rows[0].cancelable);
}

#[test]
fn jobs_registry_model_does_not_read_unhydrated_run_history() {
    let (_temp, app) = app_with_target();
    persist(
        &app,
        RunSummary::running("run-cold", "tool", Some("sast:scan".into()), "/repo").complete(),
    );

    let model = jobs_registry_model(&app, 20);

    assert!(model.rows.is_empty());
    assert_eq!(model.history_state, JobHistoryState::NotRequested);
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
    hydrate_run_history(&mut app);

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
fn jobs_and_run_focus_agree_while_live_run_is_canceling() {
    let (_temp, mut app) = app_with_target();
    let _ticket = app.jobs_mut().start(JobKind::Run, "semgrep:scan");
    let mut session = ActivitySession::new("tool-500-canceling");
    session.seed_task_sequence(vec!["semgrep:scan".to_string()]);
    session.tasks.get_mut("semgrep:scan").unwrap().state = crate::DagTaskState::Active;
    session.mark_active_tasks_canceling();

    let run_focus = activity_header_model(&session, &ActivityRouteState::default(), None, None);
    app.set_activity(Some(session));
    let jobs = jobs_registry_model(&app, 20);

    assert_eq!(jobs.rows[0].status, JobRunStatus::Canceling);
    assert_eq!(jobs.rows[0].status.label(), "canceling");
    assert!(run_focus.summary_title.contains("1 × canceling"));
}

#[test]
fn canceled_agent_slot_stays_canceling_after_agent_view_is_cleared() {
    let (_temp, mut app) = app_with_target();
    let _ticket = app.jobs_mut().start(JobKind::Agent, "agent");
    app.set_activity(Some(ActivitySession::new("agent-500-waiting")));
    assert!(app.jobs_mut().cancel(JobKind::Agent));
    app.set_agent_chat(None);

    let jobs = jobs_registry_model(&app, 20);

    assert_eq!(jobs.rows[0].run_id, "agent-500-waiting");
    assert_eq!(jobs.rows[0].status, JobRunStatus::Canceling);
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

    app.steer_queue_mut().remove_matching("queued-1").unwrap();
    let model = jobs_registry_model(&app, 20);
    assert_eq!(model.rows[0].run_id, "queued-2");
    assert_eq!(model.rows[0].label, "run verify:finding");
}

#[test]
fn jobs_registry_model_downgrades_orphaned_running_summary() {
    let (_temp, mut app) = app_with_target();
    // A crashed process leaves a "running" summary tagged with a dead PID.
    persist(
        &app,
        RunSummary::running("scan-900-dead", "scan", Some("sast:scan".into()), "/repo")
            .with_process_id(u32::MAX),
    );
    hydrate_run_history(&mut app);

    let model = jobs_registry_model(&app, 20);

    assert_eq!(
        model.rows.len(),
        1,
        "cached history: {:#?}",
        app.workbench_cache()
            .borrow()
            .cached_run_summary_entries(app.target())
    );
    // Every unix now probes liveness: Linux via `/proc/<pid>`, darwin and other
    // unix via `kill(pid, 0)`. A dead PID is therefore downgraded to
    // `interrupted` on all unix. Only non-unix (no probe) still can't verify a
    // disk `running` row with no live twin, so it renders as `Stale` ("running?").
    let expected = if cfg!(unix) {
        JobRunStatus::Interrupted
    } else {
        JobRunStatus::Stale
    };
    assert_eq!(model.rows[0].status, expected);
    assert!(!model.rows[0].cancelable);
}

#[test]
fn jobs_registry_model_marks_untwinned_disk_running_row_as_stale() {
    let (_temp, mut app) = app_with_target();
    // A `running` summary with no process_id (so no repair) and no live twin in
    // this session: liveness is unverifiable, so it must not read as running.
    persist(
        &app,
        RunSummary::running("tool-700-ghost", "tool", Some("triage:run".into()), "/repo"),
    );
    hydrate_run_history(&mut app);

    let model = jobs_registry_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].status, JobRunStatus::Stale);
    assert_eq!(model.rows[0].status.label(), "running?");
    assert!(!model.rows[0].cancelable);
}

#[test]
fn invalidated_run_history_stays_stale_until_it_is_rehydrated() {
    let (_temp, mut app) = app_with_target();
    persist(
        &app,
        RunSummary::running("run-old", "tool", None, "/repo").complete(),
    );
    hydrate_run_history(&mut app);
    assert_eq!(jobs_registry_model(&app, 20).rows.len(), 1);

    persist(
        &app,
        RunSummary::running("run-new", "tool", None, "/repo").complete(),
    );
    assert_eq!(jobs_registry_model(&app, 20).rows.len(), 1);

    app.workbench_cache()
        .borrow_mut()
        .invalidate_run_summaries();
    // Stale entries keep serving so the deck never blanks mid-refresh; the
    // hydration gate still reports the index as due for a re-read.
    let pending = jobs_registry_model(&app, 20);
    assert_eq!(pending.rows.len(), 1);
    assert_eq!(pending.history_state, JobHistoryState::Ready);
    assert!(app
        .workbench_cache()
        .borrow()
        .run_summary_entries_need_refresh(app.target().unwrap()));

    hydrate_run_history(&mut app);
    let refreshed = jobs_registry_model(&app, 20);
    assert_eq!(refreshed.history_state, JobHistoryState::Ready);
    assert_eq!(refreshed.rows.len(), 2);
}
