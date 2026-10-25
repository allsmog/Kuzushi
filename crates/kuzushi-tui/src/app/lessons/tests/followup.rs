use super::*;
use kuzushi_core::{OptionScope, OptionTarget};
use ratatui::{backend::TestBackend, Terminal};

fn copied_context() -> (tempfile::TempDir, kuzushi_core::FindingStore, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let (workspace, store, base) = fixture::prepare(root.path());
    let finding = store.list_all_findings().unwrap()[0].id.unwrap();
    let lesson = super::draft_preservation::accepted_lesson(&store, root.path(), finding);
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.open_lessons();
    app.router.lessons.finding_id = Some(finding);
    app.spawn_lesson_action(
        "threat-model:reuse-lessons",
        serde_json::json!({"threatModelRef":base,"lessons":[lesson.reference().unwrap()]}),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !app.poll_lesson_write() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert!(app.router.lessons.saved_context.is_some());
    (root, store, app)
}

#[test]
fn followup_binds_exact_saved_context_and_preserves_options_without_approval_or_work() {
    let (root, store, mut app) = copied_context();
    let reference = app.router.lessons.saved_context.clone().unwrap();
    let decisions = store.list_all_review_decisions().unwrap();
    app.option_store_mut().set_value(
        OptionScope::Global,
        OptionTarget::Tool("sast:scan".into()),
        "taskMode",
        serde_json::json!("manual"),
    );
    app.option_store_mut().set_value(
        OptionScope::Global,
        OptionTarget::Tool("sast:scan".into()),
        "tasks",
        serde_json::json!(["agentic"]),
    );
    app.option_store_mut().set_value(
        OptionScope::Global,
        OptionTarget::Tool("sast:scan".into()),
        "paths",
        serde_json::json!(["hello.txt"]),
    );
    let options = app.option_store().clone();
    app.set_input("retained composer");
    app.router.default_scroll_mut().set(7);
    let before = app.router.lessons.clone();
    app.handle_lesson_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Campaign);
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(
        (
            config.trials,
            config.requested_workers,
            config.study.max_job_attempts
        ),
        (3, 1, 1)
    );
    assert!(!config.study.approved() && config.study.plan_identity().is_none());
    assert_eq!(config.study.max_provider_calls, None);
    let input = config.study.scan_input.as_ref().unwrap();
    assert_eq!(input["threatModelRef"], serde_json::json!(reference));
    assert_eq!(input["tasks"], serde_json::json!(["agentic"]));
    assert_eq!(input["paths"], serde_json::json!(["hello.txt"]));
    assert!(config
        .notice
        .as_ref()
        .unwrap()
        .contains("historical cost is unknown"));
    assert_eq!(
        app.option_store().effective_stored_values("sast:scan"),
        options.effective_stored_values("sast:scan")
    );
    assert_eq!(store.list_all_review_decisions().unwrap(), decisions);
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Lessons);
    assert_eq!(app.router.lessons, before);
    assert_eq!(app.input(), "retained composer");
    assert_eq!(app.router.default_scroll().offset(), 7);
}

#[test]
fn missing_copy_and_retired_guidance_are_honest_nonlaunching_failures() {
    let (_root, _store, mut app) = copied_context();
    app.router.lessons.saved_context = None;
    app.plan_lesson_context_scan();
    assert_eq!(app.shell_view(), ShellView::Lessons);
    assert!(app
        .router
        .lessons
        .notice
        .as_ref()
        .unwrap()
        .contains("Use u"));
    assert!(app.router.campaign().batch_scan_config.is_none());
    let (_root, store, mut app) = copied_context();
    let lesson = store.finding_lessons(50, 0).unwrap().rows[0].clone();
    store
        .review_finding_lesson(
            &lesson.reference().unwrap(),
            LessonState::Retired,
            "Retired owned guidance".into(),
        )
        .unwrap();
    app.plan_lesson_context_scan();
    assert_eq!(app.shell_view(), ShellView::Lessons);
    assert!(app
        .router
        .lessons
        .notice
        .as_ref()
        .unwrap()
        .contains("retired"));
    assert!(app.router.campaign().batch_scan_config.is_none());
}

#[test]
fn existing_open_study_is_never_replaced_by_a_followup() {
    let (_root, _store, mut app) = copied_context();
    app.open_batch_scan_config(None);
    let prior = app.router.campaign().batch_scan_config.clone();
    app.set_shell_view(ShellView::Lessons);
    app.plan_lesson_context_scan();
    assert_eq!(app.router.campaign().batch_scan_config, prior);
    assert!(app
        .router
        .lessons
        .notice
        .as_ref()
        .unwrap()
        .contains("Return to the open study"));
}

#[test]
fn followup_shortcut_respects_the_composer_and_lesson_editor() {
    let (_root, _store, mut app) = copied_context();
    app.set_input_mode(InputMode::Prompt);
    app.set_input("retained ");
    app.reduce_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
    assert_eq!(app.input(), "retained s");
    assert!(app.router.campaign().batch_scan_config.is_none());
    app.set_input_mode(InputMode::Navigate);
    app.handle_lesson_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
    assert!(app.router.campaign().batch_scan_config.is_none());
    app.begin_lesson_draft(false);
    app.handle_lesson_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
    assert!(app.router.lessons.form_visible);
    assert!(app.router.campaign().batch_scan_config.is_none());
    assert!(app.router.lessons.form.as_ref().unwrap().fields[0]
        .text()
        .ends_with('s'));
}

#[test]
fn context_followup_action_is_visible_at_every_supported_size_and_plain_output() {
    let (_root, _store, app) = copied_context();
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("s Plan follow-up"), "{width}x{height}");
    }
    assert!(crate::renderer::render_plain_app(&app, 40).contains("s Plan follow-up"));
}
