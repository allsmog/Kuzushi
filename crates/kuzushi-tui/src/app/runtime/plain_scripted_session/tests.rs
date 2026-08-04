use super::*;
use kuzushi_core::run_lifecycle::RunItemStatus;

#[test]
fn interactive_workflow_commands_are_rejected_in_plain_mode() {
    for command in [
        "map",
        "/map",
        "scan",
        "/scan",
        "review",
        "/review",
        "prove",
        "/prove",
        "fix",
        "/fix",
        "full",
        "/full",
        "pipeline",
        "/pipeline",
    ] {
        let mut app = ShellApp::new(V2Config::default(), None);

        let report = execute_plain_scripted_session(&mut app, &[command], 80);

        assert_eq!(report.outcome, PlainCommandOutcome::Rejected, "{command}");
        assert_eq!(report.outcome.exit_code(), 1, "{command}");
        assert!(
            report.output.contains("interactive TUI workflow"),
            "{}",
            report.output
        );
        assert!(
            report.output.contains("for scripts use `kuzushi scan"),
            "{}",
            report.output
        );
        assert!(!app.has_running_work(), "{command}");
        assert!(app.scan().is_none(), "{command}");
    }
}

#[test]
fn full_aliases_with_explicit_target_are_rejected_in_plain_mode() {
    let target = tempfile::tempdir().unwrap();
    for verb in ["full", "/full", "pipeline", "/pipeline"] {
        let mut app = ShellApp::new(V2Config::default(), None);
        let command = format!("{verb} {}", target.path().display());

        let report = execute_plain_scripted_session(&mut app, &[&command], 80);

        assert_eq!(report.outcome, PlainCommandOutcome::Rejected, "{command}");
        assert_eq!(report.outcome.exit_code(), 1, "{command}");
        assert!(
            report
                .output
                .contains("kuzushi --target <target> run sast:scan"),
            "{command}"
        );
        assert!(app.target().is_none(), "{command}");
        assert!(app.scan().is_none(), "{command}");
        assert!(!target.path().join(".kuzushi").exists(), "{command}");
    }
}

#[test]
fn queued_workflow_commands_cannot_bypass_plain_mode_rejection() {
    let target = tempfile::tempdir().unwrap();
    let commands = [
        "queue scan".to_string(),
        "queue queue scan".to_string(),
        format!("queue full {}", target.path().display()),
        format!("queue pipeline {}", target.path().display()),
    ];

    for command in commands {
        let mut app = ShellApp::new(V2Config::default(), None);

        let report = execute_plain_scripted_session(&mut app, &[&command], 80);

        assert_eq!(report.outcome, PlainCommandOutcome::Rejected, "{command}");
        assert_eq!(report.outcome.exit_code(), 1, "{command}");
        assert!(
            report.output.contains("interactive TUI workflow"),
            "{}",
            report.output
        );
        assert!(app.target().is_none(), "{command}");
        assert!(!app.has_running_work(), "{command}");
        assert!(app.scan().is_none(), "{command}");
    }
}

#[test]
fn legacy_scan_target_in_plain_mode_points_to_headless_commands() {
    let target = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let command = format!("scan {}", target.path().display());

    let report = execute_plain_scripted_session(&mut app, &[&command], 160);

    assert_eq!(report.outcome, PlainCommandOutcome::Rejected);
    assert_eq!(report.outcome.exit_code(), 1);
    assert!(report.output.contains("`kuzushi scan <target>`"));
    assert!(report
        .output
        .contains("`kuzushi --target <target> run sast:scan`"));
    assert!(!report.output.contains("`target <path>` then `scan`"));
    assert!(app.target().is_none());
    assert!(!app.has_running_work());
}

#[test]
fn unknown_command_rejection_is_carried_by_the_typed_reduction() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let submission = submit_plain_line(&mut app, "definitely-not-a-command");

    assert_eq!(submission, PlainSubmission::Rejected);
}

#[test]
fn unrelated_error_emission_does_not_reclassify_an_accepted_command() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let submission = submit_plain_line(&mut app, "help");
    app.log("error", "unrelated background diagnostic");

    let outcome = plain_command_outcome(&app, None, submission, PlainWorkOutcome::Completed);

    assert_eq!(outcome, PlainCommandOutcome::NoRunCompleted);
}

#[test]
fn plain_commands_bypass_modal_onboarding_without_selecting_a_model() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    assert_eq!(app.shell_view(), ShellView::Setup);

    let report = execute_plain_scripted_session(&mut app, &["findings"], 80);

    assert_eq!(app.config().model, None);
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert!(report.output.contains("findings"), "{}", report.output);
}

#[test]
fn every_typed_terminal_status_has_an_explicit_exit_mapping() {
    use kuzushi_core::run_lifecycle::RunItemStatus;

    let cases = [
        (RunItemStatus::Pending, 1),
        (RunItemStatus::Running, 1),
        (RunItemStatus::Completed, 0),
        (RunItemStatus::Partial, 1),
        (RunItemStatus::Skipped, 0),
        (RunItemStatus::Failed, 1),
        (RunItemStatus::Canceled, 1),
        (RunItemStatus::Interrupted, 1),
    ];

    for (status, expected_exit) in cases {
        let outcome = PlainCommandOutcome::RunTerminal {
            run_id: kuzushi_core::run_lifecycle::RunId::parse("run-exit-map").unwrap(),
            status,
        };
        assert_eq!(outcome.exit_code(), expected_exit);
    }
    assert_eq!(PlainCommandOutcome::NoRunCompleted.exit_code(), 0);
    assert_eq!(PlainCommandOutcome::Rejected.exit_code(), 1);
    assert_eq!(PlainCommandOutcome::Quarantined.exit_code(), 1);
    assert_eq!(PlainCommandOutcome::InvariantFailure.exit_code(), 1);
}

#[test]
fn session_outcome_keeps_the_first_nonzero_command_outcome() {
    let completed = terminal_command_outcome("run-completed", RunItemStatus::Completed);
    let skipped = terminal_command_outcome("run-skipped", RunItemStatus::Skipped);
    let partial = terminal_command_outcome("run-partial", RunItemStatus::Partial);
    assert_eq!(
        PlainCommandOutcome::NoRunCompleted.merge(skipped.clone()),
        skipped
    );
    assert_eq!(
        completed.merge(PlainCommandOutcome::NoRunCompleted),
        terminal_command_outcome("run-completed", RunItemStatus::Completed)
    );
    assert_eq!(
        partial.clone().merge(PlainCommandOutcome::Rejected),
        partial
    );
}

#[test]
fn fresh_typed_terminal_controls_exit_and_stale_terminal_does_not() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let before = plain_terminal_snapshot(&app);
    app.log("result", "pass exit_hint=0");
    app.set_activity(Some(terminal_activity(
        "run-partial",
        RunItemStatus::Partial,
    )));

    let outcome = plain_command_outcome(
        &app,
        before.as_ref(),
        PlainSubmission::RunExpected,
        PlainWorkOutcome::Completed,
    );

    assert_eq!(
        outcome,
        terminal_command_outcome("run-partial", RunItemStatus::Partial)
    );
    let stale = plain_terminal_snapshot(&app);
    assert_eq!(
        plain_command_outcome(
            &app,
            stale.as_ref(),
            PlainSubmission::NoRunExpected,
            PlainWorkOutcome::Completed,
        ),
        PlainCommandOutcome::NoRunCompleted
    );
}

#[test]
fn typed_disk_projection_closes_live_delivery_tail_without_legacy_inference() {
    let temp = tempfile::tempdir().unwrap();
    let run_id = kuzushi_core::run_artifacts::new_run_id("plain-typed-exit");
    let observation =
        kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(temp.path(), &run_id).unwrap();
    observation
        .emit(kuzushi_core::run_lifecycle::RunItemRecord::new(
            kuzushi_core::run_lifecycle::RunItemId::new(),
            kuzushi_core::run_lifecycle::RunItemSource::Workflow,
            kuzushi_core::run_lifecycle::RunItemV1::TerminalOutcome {
                status: kuzushi_core::run_lifecycle::RunItemStatus::Interrupted,
                summary: kuzushi_core::run_lifecycle::SafeText::operator_visible("interrupted"),
                cost: kuzushi_core::runtime::RuntimeCostReport::INCOMPLETE_ZERO,
                continuation: kuzushi_core::run_lifecycle::WorkflowContinuation::NoFurtherAction {
                    reason: kuzushi_core::run_lifecycle::SafeText::operator_visible("inspect logs"),
                },
            },
        ))
        .unwrap();
    observation.flush().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_activity(Some(ActivitySession::new(&run_id)));

    let snapshot = plain_terminal_snapshot(&app).unwrap();

    assert_eq!(
        snapshot.status,
        kuzushi_core::run_lifecycle::RunItemStatus::Interrupted
    );
    assert_eq!(
        plain_terminal_outcome(snapshot),
        terminal_command_outcome(
            &run_id,
            kuzushi_core::run_lifecycle::RunItemStatus::Interrupted,
        )
    );
}

#[test]
fn rendered_result_words_do_not_control_exit() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.log("result", "failed partial canceled interrupted exit_hint=1");
    let line = app.log_lines_mut_for_test().last_mut().unwrap();
    line.prefix = "error".to_string();
    line.body = "rewritten renderer text".to_string();

    let outcome = plain_command_outcome(
        &app,
        plain_terminal_snapshot(&app).as_ref(),
        PlainSubmission::NoRunExpected,
        PlainWorkOutcome::Completed,
    );

    assert_eq!(outcome, PlainCommandOutcome::NoRunCompleted);
}

#[test]
fn accepted_run_without_a_fresh_terminal_is_an_invariant_failure() {
    let app = ShellApp::new(V2Config::default(), None);

    let outcome = plain_command_outcome(
        &app,
        None,
        PlainSubmission::RunExpected,
        PlainWorkOutcome::Completed,
    );

    assert_eq!(outcome, PlainCommandOutcome::InvariantFailure);
}

#[test]
fn degraded_terminal_projection_is_an_invariant_failure() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut activity = terminal_activity("run-degraded", RunItemStatus::Completed);
    activity.run_projection.health = kuzushi_core::run_lifecycle::ProjectionHealth::Degraded {
        valid_through_seq: 0,
        reason: "corrupt typed stream".to_string(),
    };
    app.set_activity(Some(activity));

    let outcome = plain_command_outcome(
        &app,
        None,
        PlainSubmission::RunExpected,
        PlainWorkOutcome::Completed,
    );

    assert_eq!(outcome, PlainCommandOutcome::InvariantFailure);
}

#[test]
fn durability_failed_terminal_projection_is_an_invariant_failure() {
    use kuzushi_core::run_lifecycle::{PersistenceFailureStage, RunItemWriterFault, SafeText};
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut activity = terminal_activity("run-durability", RunItemStatus::Completed);
    activity.record_run_item_writer_fault(RunItemWriterFault {
        stage: PersistenceFailureStage::Sync,
        last_durable_seq: 0,
        detail: SafeText::operator_visible("sync failed"),
        execution_may_have_occurred: true,
    });
    app.set_activity(Some(activity));

    let outcome = plain_command_outcome(
        &app,
        None,
        PlainSubmission::RunExpected,
        PlainWorkOutcome::Completed,
    );

    assert_eq!(outcome, PlainCommandOutcome::InvariantFailure);
}

#[test]
fn delivery_tail_at_session_end_is_an_invariant_failure() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut activity = terminal_activity("run-catching-up", RunItemStatus::Completed);
    activity.observe_committed_range(kuzushi_core::run_lifecycle::CommittedRange {
        first_seq: 1,
        through_seq: 1,
    });
    app.set_activity(Some(activity));

    let outcome = plain_command_outcome(
        &app,
        None,
        PlainSubmission::RunExpected,
        PlainWorkOutcome::Completed,
    );

    assert_eq!(outcome, PlainCommandOutcome::InvariantFailure);
}

#[test]
fn nonterminal_status_cannot_masquerade_as_a_run_terminal() {
    let snapshot = plain_terminal_snapshot_for_test("run-running", RunItemStatus::Running);

    assert_eq!(
        plain_terminal_outcome(snapshot),
        PlainCommandOutcome::InvariantFailure
    );
}

#[test]
fn quarantined_worker_fails_plain_session_without_waiting_for_thread_exit() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let ticket = app.jobs_mut().start(JobKind::Run, "hung:tool");
    let generation = ticket.generation();
    let now = std::time::Instant::now();
    app.jobs_mut()
        .schedule_unresponsive_escalation(JobKind::Run, generation, now);
    assert!(app
        .jobs_mut()
        .quarantine_unresponsive_slots(now + WORKER_UNRESPONSIVE_GRACE));

    let report = execute_plain_scripted_session(&mut app, &["help"], 80);

    assert_eq!(report.outcome, PlainCommandOutcome::Quarantined);
    assert!(report.output.contains("worker remained unresponsive"));
    assert!(app.jobs().is_quarantined(JobKind::Run));
    app.jobs_mut().finish(JobKind::Run);
    ticket.complete();
}

#[test]
fn scripted_replay_hydrates_artifacts_before_plain_rendering() {
    let temp = tempfile::tempdir().unwrap();
    let run_id = "run-plain-replay";
    let summary =
        kuzushi_core::RunSummary::running(run_id, "tool", None, temp.path().display().to_string())
            .complete();
    kuzushi_core::write_run_summary(temp.path(), &summary).unwrap();
    let observation =
        kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(temp.path(), run_id).unwrap();
    observation
        .emit(kuzushi_core::run_lifecycle::RunItemRecord::new(
            kuzushi_core::run_lifecycle::RunItemId::new(),
            kuzushi_core::run_lifecycle::RunItemSource::Workflow,
            kuzushi_core::run_lifecycle::RunItemV1::TerminalOutcome {
                status: RunItemStatus::Completed,
                summary: kuzushi_core::run_lifecycle::SafeText::operator_visible(
                    "Replay fixture completed",
                ),
                cost: kuzushi_core::runtime::RuntimeCostReport::known(
                    kuzushi_core::runtime::RuntimeCost::ZERO,
                ),
                continuation: kuzushi_core::run_lifecycle::WorkflowContinuation::NoFurtherAction {
                    reason: kuzushi_core::run_lifecycle::SafeText::operator_visible(
                        "run completed",
                    ),
                },
            },
        ))
        .unwrap();
    observation.flush().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));

    let report = execute_plain_scripted_session(&mut app, &[&format!("replay {run_id}")], 180);

    assert!(report.output.contains("OUTCOME"), "{}", report.output);
    assert!(
        report.output.contains("Replay fixture completed"),
        "{}",
        report.output
    );
    assert!(
        !report.output.contains("loading artifact"),
        "{}",
        report.output
    );
}

fn terminal_activity(
    run_id: &str,
    status: kuzushi_core::run_lifecycle::RunItemStatus,
) -> ActivitySession {
    let mut activity = ActivitySession::new(run_id);
    activity.run_projection.terminal = Some(kuzushi_core::run_lifecycle::TerminalProjection {
        item_id: kuzushi_core::run_lifecycle::RunItemId::new(),
        status,
        summary: kuzushi_core::run_lifecycle::SafeText::operator_visible("terminal"),
        cost: kuzushi_core::runtime::RuntimeCostReport::INCOMPLETE_ZERO,
        continuation: kuzushi_core::run_lifecycle::WorkflowContinuation::NoFurtherAction {
            reason: kuzushi_core::run_lifecycle::SafeText::operator_visible("done"),
        },
    });
    activity
}

fn terminal_command_outcome(run_id: &str, status: RunItemStatus) -> PlainCommandOutcome {
    PlainCommandOutcome::RunTerminal {
        run_id: kuzushi_core::run_lifecycle::RunId::parse(run_id).unwrap(),
        status,
    }
}

fn plain_terminal_snapshot_for_test(run_id: &str, status: RunItemStatus) -> PlainTerminalSnapshot {
    let app = ShellApp::new(V2Config::default(), None);
    PlainTerminalSnapshot {
        run_id: kuzushi_core::run_lifecycle::RunId::parse(run_id).unwrap(),
        item_id: kuzushi_core::run_lifecycle::RunItemId::new(),
        status,
        health: app
            .activity()
            .map(ActivitySession::effective_run_lifecycle_health)
            .unwrap_or_else(|| {
                kuzushi_core::run_lifecycle::RunProjection::default().lifecycle_health()
            }),
    }
}
