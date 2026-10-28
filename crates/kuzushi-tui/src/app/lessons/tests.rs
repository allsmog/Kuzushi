use super::*;
mod draft_preservation;
mod fixture;
mod followup;
mod pagination;
mod reader;
mod replacement;
mod supporting_sources;

#[test]
fn lesson_preparation_failure_is_visible_without_losing_draft_or_focus() {
    let root = tempfile::tempdir().unwrap();
    let (workspace, store, _) = fixture::prepare(root.path());
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.open_lessons();
    app.router.lessons.finding_id = store.list_all_findings().unwrap()[0].id;
    app.plan_lesson_generation();
    app.set_shell_view(ShellView::Help);
    app.cache_lesson_planning_failure("campaign:approve-allowance", "Frozen plan rejected");
    let notice = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .notice
        .as_ref()
        .unwrap();
    assert!(notice.contains("Frozen plan rejected"));
    assert!(notice.contains("No model request started"));
    assert_eq!(app.shell_view(), ShellView::Help);
    assert!(app.context_generation().unwrap().is_lesson());
    assert!(store.finding_lessons(50, 0).unwrap().rows.is_empty());
}

#[test]
fn lesson_generation_preserves_drafts_and_shared_accounting_before_spending() {
    let root = tempfile::tempdir().unwrap();
    let (workspace, store, _) = fixture::prepare(root.path());
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.open_lessons();
    app.router.lessons.finding_id = store.list_all_findings().unwrap()[0].id;
    app.begin_lesson_draft(false);
    app.router.lessons.form.as_mut().unwrap().fields[0].insert("Retained human draft");
    app.router.lessons.form_visible = false;
    app.plan_lesson_generation();
    let id = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .investigation_id
        .clone();
    assert!(app.context_generation().unwrap().is_lesson());
    assert_eq!(
        app.context_generation()
            .unwrap()
            .action(app.router.campaign().batch_scan_config.as_ref().unwrap()),
        "Prepare lesson draft"
    );
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    app.plan_lesson_generation();
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study
            .investigation_id,
        id
    );
    assert_eq!(
        app.router.lessons.form.as_ref().unwrap().fields[0].text(),
        "Retained human draft"
    );
    assert!(store.finding_lessons(50, 0).unwrap().rows.is_empty());
}

#[test]
fn missing_pinned_lesson_never_targets_an_unrelated_row() {
    let root = tempfile::tempdir().unwrap();
    let (workspace, store, _) = fixture::prepare(root.path());
    let id = store.list_all_findings().unwrap()[0].id.unwrap();
    let content = LessonContent {
        title: "Visible draft".into(),
        text: "Review source".into(),
        applicability: "Source review".into(),
        limitations: "Historical".into(),
    };
    store
        .draft_finding_lesson(content, store.lesson_origin(root.path(), id).unwrap(), None)
        .unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.open_lessons();
    app.workbench_cache().borrow_mut().lesson_pages.insert(
        (workspace.root().into(), 0),
        Ok(store.finding_lessons(50, 0).unwrap()),
    );
    app.router.lessons.pinned_id = Some("other-lesson".into());
    assert!(app.selected_lesson().is_none());
    app.begin_lesson_review(LessonState::Accepted);
    assert!(app.router.lessons.form.is_none());
    app.handle_lesson_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    assert!(app.selected_lesson().is_some());
}

#[test]
fn lesson_writer_preserves_focus_and_confirmation_is_explicit() {
    let root = tempfile::tempdir().unwrap();
    let (workspace, store, _base) = fixture::prepare(root.path());
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.open_lessons();
    app.router.lessons.finding_id = store.list_all_findings().unwrap()[0].id;
    app.begin_lesson_draft(false);
    for (field, text) in app
        .router
        .lessons
        .form
        .as_mut()
        .unwrap()
        .fields
        .iter_mut()
        .zip([
            "Greeting lesson",
            "Inspect recorded greeting evidence.",
            "Manual source review",
            "Historical guidance only.",
        ])
    {
        field.insert(text);
    }
    app.handle_lesson_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(store.finding_lessons(50, 0).unwrap().rows.is_empty());
    app.handle_lesson_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    app.set_shell_view(ShellView::Help);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !app.poll_lesson_write() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert_eq!(app.shell_view(), ShellView::Help);
    assert!(app.router.lessons.form.is_none());
    assert!(!app.router.lessons.form_visible);
    assert_eq!(
        store.finding_lessons(50, 0).unwrap().rows[0].state,
        LessonState::Draft
    );
}

fn app() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(root.path()).unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.open_lessons();
    app.set_input_mode(InputMode::Navigate);
    app.router.lessons.finding_id = Some(1);
    (root, app)
}

#[test]
fn lesson_form_owns_paste_preserves_composer_and_retains_draft() {
    let (_root, mut app) = app();
    app.editor_mut().set_input("retained composer");
    app.begin_lesson_draft(false);
    app.paste_lesson_field("Human note\nUnicode café");
    assert_eq!(app.editor().input(), "retained composer");
    app.handle_lesson_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(!app.router.lessons.form_visible);
    app.handle_lesson_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
    assert!(app.router.lessons.form_visible);
    assert_eq!(
        app.router.lessons.form.as_ref().unwrap().fields[0].text(),
        "Human note\nUnicode café"
    );
}

#[test]
fn empty_fields_cannot_reach_confirmation_and_review_never_writes_on_first_enter() {
    let (_root, mut app) = app();
    app.begin_lesson_draft(false);
    app.handle_lesson_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(!app.router.lessons.form.as_ref().unwrap().confirming);
    for field in &mut app.router.lessons.form.as_mut().unwrap().fields {
        field.insert("Reviewed text");
    }
    app.handle_lesson_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.router.lessons.form.as_ref().unwrap().confirming);
    assert!(app.runtime_state.lesson_write.is_none());
    let workspace = kuzushi_core::WorkspaceTarget::new(app.target().unwrap()).unwrap();
    let store = kuzushi_core::FindingStore::open_read_only(workspace.findings_db_path()).unwrap();
    assert!(store.finding_lessons(50, 0).unwrap().rows.is_empty());
}

#[test]
fn lesson_editor_keeps_active_text_and_failure_visible_across_terminal_sizes() {
    use ratatui::{backend::TestBackend, Terminal};
    let (_root, mut app) = app();
    app.begin_lesson_draft(false);
    let form = app.router.lessons.form.as_mut().unwrap();
    form.focused = 1;
    form.fields[1].insert("Unicode café");
    app.handle_lesson_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    for (width, height) in [(40, 12), (60, 20), (80, 24), (120, 36)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(
            rendered.contains("Unicode café"),
            "Active field hidden at {width}x{height}: {rendered}"
        );
        assert!(
            rendered.contains("must contain"),
            "Validation hidden at {width}x{height}: {rendered}"
        );
    }
}
