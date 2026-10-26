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
    let (_root, store, mut app) = copied_context();
    let page = store.finding_lessons(50, 0).unwrap();
    let title = page.rows[0].content.title.clone();
    app.workbench_cache()
        .borrow_mut()
        .lesson_pages
        .insert((app.target_owned().unwrap(), 0), Ok(page));
    let before = app.router.lessons.clone();
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let text = browser_text(&app, width, height);
        assert!(text.contains("s Plan follow-up"), "{width}x{height}");
        let readable = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(readable.contains(&title), "{width}x{height}: {readable}");
        assert!(
            readable.contains("Accepted"),
            "{width}x{height}: {readable}"
        );
        if height == 12 {
            assert!(readable.contains("a/r/t review"), "{readable}");
            assert!(readable.contains("u copy"), "{readable}");
        }
    }
    let plain = crate::renderer::render_plain_app(&app, 40);
    for label in [
        "s Plan follow-up",
        "n draft",
        "g model",
        "a/r/t review",
        "u copy",
    ] {
        assert!(plain.contains(label), "missing {label}: {plain}");
    }
    assert_eq!(app.router.lessons, before);
}

#[test]
fn compact_loading_empty_and_failed_pages_keep_state_and_recovery_visible() {
    let (_root, store, mut app) = copied_context();
    app.set_viewport(crate::TerminalViewport::new(40, 12));
    let key = (app.target_owned().unwrap(), 0);
    let mut empty = store.finding_lessons(50, 0).unwrap();
    empty.rows.clear();
    let states = [
        (None, "Loading saved lessons"),
        (Some(Ok(empty)), "No saved lessons"),
        (
            Some(Err("Owned read failure".into())),
            "Lessons unavailable",
        ),
    ];
    for (state, caption) in states {
        app.workbench_cache().borrow_mut().lesson_pages.remove(&key);
        if let Some(page) = state {
            app.workbench_cache()
                .borrow_mut()
                .lesson_pages
                .insert(key.clone(), page);
        }
        let text = browser_text(&app, 40, 12);
        for label in [caption, "n draft", "g model", "R refresh"] {
            assert!(text.contains(label), "missing {label}: {text}");
        }
        assert!(app.runtime_state.lesson_write.is_none());
        assert!(app.router.campaign().batch_scan_config.is_none());
    }
}

fn browser_text(app: &ShellApp, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}
