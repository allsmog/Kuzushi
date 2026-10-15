use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn fixture() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("note.txt"), "Owned inert code read.\n").unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(root.path()).unwrap();
    let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("labeled-synthetic-observation", root.path(), "running")
        .unwrap();
    let finding = Finding::new_tool(
        "fixture",
        "owned",
        "note.txt",
        1,
        None,
        kuzushi_core::Severity::Low,
        "Owned source form fixture",
    );
    store
        .insert_finding("labeled-synthetic-observation", &finding)
        .unwrap();
    let finding = store
        .get_finding_by_fingerprint(&finding.fingerprint)
        .unwrap()
        .unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_findings(vec![finding]);
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    (root, app)
}

fn press(app: &mut ShellApp, code: KeyCode, modifiers: KeyModifiers) {
    app.handle_source_review_key(KeyEvent::new(code, modifiers))
        .unwrap();
}

fn settle(app: &mut ShellApp) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !app.poll_source_review() {
        assert!(
            std::time::Instant::now() < deadline,
            "source worker timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn reason_reader_discloses_an_invalid_selection_without_panicking() {
    let (_root, mut app) = fixture();
    app.open_current_source_review();
    let form = app.source_review_form_mut().unwrap();
    form.mode = SourceReviewMode::Reason;
    form.verdict = usize::MAX;
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(
            text.contains("Verdict: not selected"),
            "{width}x{height}: {text}"
        );
    }
    assert!(!app.has_running_work());
    assert_eq!(app.source_review_form().unwrap().decision_id, None);
}

#[test]
fn source_form_captures_reads_and_saves_one_explicit_decision() {
    let (root, mut app) = fixture();
    app.open_current_source_review();
    assert_eq!(
        app.source_review_form().unwrap().mode,
        SourceReviewMode::Intro
    );
    assert!(!app.has_running_work());
    press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    settle(&mut app);
    assert_eq!(
        app.source_review_form().unwrap().mode,
        SourceReviewMode::Reading
    );
    assert_eq!(
        app.source_review_form().unwrap().capture.as_ref().unwrap()["citedSourceCode"],
        "Owned inert code read.\n"
    );
    press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    assert!(app.insert_source_review_paste("Owned code reviewed.\nUncertainty retained."));
    press(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
    assert_eq!(
        app.source_review_form().unwrap().mode,
        SourceReviewMode::Confirm
    );
    press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    settle(&mut app);
    assert_eq!(
        app.source_review_form().unwrap().mode,
        SourceReviewMode::Saved
    );
    assert!(app.source_review_form().unwrap().decision_id.is_some());
    let workspace = kuzushi_core::WorkspaceTarget::new(root.path()).unwrap();
    let store = kuzushi_core::FindingStore::open_read_only(workspace.findings_db_path()).unwrap();
    assert_eq!(
        store
            .list_review_decisions(app.findings()[0].id.unwrap())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn modal_paste_and_back_preserve_the_composer_and_reason() {
    let (_root, mut app) = fixture();
    app.set_input("unsent\ncomposer");
    app.set_cursor(3);
    app.open_current_source_review();
    app.source_review_form_mut().unwrap().mode = SourceReviewMode::Reason;
    app.reduce_paste("review\r\nreason");
    assert_eq!(app.input(), "unsent\ncomposer");
    assert_eq!(app.cursor(), 3);
    press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    assert!(app.source_review_form().is_none());
    app.open_current_source_review();
    assert!(app
        .source_review_form()
        .unwrap()
        .reason
        .text()
        .contains("review"));
}

#[test]
fn source_drift_refuses_save_and_keeps_the_reviewed_reason() {
    let (root, mut app) = fixture();
    app.open_current_source_review();
    press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    settle(&mut app);
    app.source_review_form_mut().unwrap().mode = SourceReviewMode::Reason;
    app.insert_source_review_paste("Operator reviewed the original captured bytes.");
    press(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
    std::fs::write(root.path().join("note.txt"), "Different source.\n").unwrap();
    press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    settle(&mut app);
    let form = app.source_review_form().unwrap();
    assert_eq!(form.mode, SourceReviewMode::Confirm);
    assert!(form
        .notice
        .as_ref()
        .unwrap()
        .contains("Source content changed"));
    assert!(form.reason.text().contains("original captured bytes"));
    assert!(form.decision_id.is_none());
}

#[test]
fn closing_during_capture_cancels_without_stealing_later_focus() {
    let (_root, mut app) = fixture();
    app.open_current_source_review();
    press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    app.set_shell_view(ShellView::Logs);
    app.set_input("later draft");
    app.set_cursor(3);
    settle(&mut app);
    assert!(app.source_review_form().is_none());
    assert_eq!(app.shell_view(), ShellView::Logs);
    assert_eq!(app.input(), "later draft");
    assert_eq!(app.cursor(), 3);
    assert!(!app.has_running_work());
}

#[test]
fn empty_reason_keeps_the_form_open_with_an_explicit_message() {
    let (_root, mut app) = fixture();
    app.open_current_source_review();
    app.source_review_form_mut().unwrap().mode = SourceReviewMode::Reason;
    press(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
    assert_eq!(
        app.source_review_form().unwrap().mode,
        SourceReviewMode::Reason
    );
    assert!(app
        .source_review_form()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("Add a reason"));
}
