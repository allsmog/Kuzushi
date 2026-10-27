use super::*;
use crate::renderer::render_app;
use ratatui::{backend::TestBackend, Terminal};

#[test]
fn recovery_hydration_emits_one_warning_and_transcript_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let recovery = kuzushi_core::RecoveredRun {
        run_id: "run-recovered-12345678".to_string(),
        reason: "run process 99 is no longer running".to_string(),
    };

    app.apply_view_hydration_drain(run_history_hydration(temp.path(), vec![recovery]));
    app.apply_view_hydration_drain(run_history_hydration(temp.path(), Vec::new()));

    let notice = app.advisory().notice.as_ref().expect("recovery notice");
    assert_eq!(notice.severity, crate::NoticeSeverity::Warn);
    assert!(notice.message.contains("Recovered 1 abandoned run"));
    assert!(notice.message.contains("open `jobs` or `replay"));
    assert!(!app.notice_captures_escape());
    assert_eq!(
        app.log_lines()
            .iter()
            .filter(|line| line.body.contains("Recovered 1 abandoned run"))
            .count(),
        1
    );
}

#[test]
fn recovery_hydration_preserves_study_navigation_and_numeric_editing() {
    use crate::app::BatchScanConfigRow;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.open_batch_scan_config(None);
        app.reduce_resize(width, height);
        app.set_input("held study draft");
        app.set_cursor(4);
        inject_recovery_notice(&mut app, temp.path());
        app.reduce_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        let config = app
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap();
        assert_eq!(config.cursor, 1);
        config.begin_number_edit(BatchScanConfigRow::Attempts);
        app.reduce_paste("2");
        inject_recovery_notice(&mut app, temp.path());
        app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
        assert_eq!(config.study.max_job_attempts, 2);
        assert!(config.number_edit.is_none());
        assert!(!app.study_notice_captures_escape());
        assert_eq!((app.input(), app.cursor()), ("held study draft", 4));
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        assert!(!format!("{:?}", terminal.backend().buffer()).contains("ATTENTION:"));
    }
}

#[test]
fn recovery_hydration_keeps_an_existing_foreground_failure() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_error_notice("report", "Could not save the report");
    inject_recovery_notice(&mut app, temp.path());
    let notice = app.advisory().notice.as_ref().unwrap();
    assert_eq!(notice.severity, crate::NoticeSeverity::Error);
    assert_eq!(notice.message, "Could not save the report");
    assert!(app.notice_captures_escape());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("Recovered 1 abandoned run")));
}

fn inject_recovery_notice(app: &mut ShellApp, target: &Path) {
    let recovery = kuzushi_core::RecoveredRun {
        run_id: "run-recovered-12345678".into(),
        reason: "run process is no longer running".into(),
    };
    app.apply_view_hydration_drain(run_history_hydration(target, vec![recovery]));
}

fn run_history_hydration(
    target: &Path,
    newly_recovered: Vec<kuzushi_core::RecoveredRun>,
) -> ViewHydrationDrain {
    ViewHydrationDrain {
        results: vec![ViewHydrationResult {
            target: target.to_path_buf(),
            key: ViewHydrationKey::RunSummaryEntries,
            value: ViewHydrationValue::RunSummaryEntries(RunSummaryEntriesHydration {
                state: RunSummaryEntriesState::Ready(Vec::new()),
                newly_recovered,
            }),
        }],
        failures: Vec::new(),
    }
}
