use super::*;

#[test]
fn another_lesson_action_never_silently_replaces_unfinished_text() {
    for action in ['n', 'e', 'a', 'r', 't'] {
        let (_root, mut app) = app_with_accepted_lesson();
        app.editor_mut().set_input("Retained composer");
        app.begin_lesson_draft(false);
        app.paste_lesson_field("Unsubmitted title");
        app.handle_lesson_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        app.paste_lesson_field("Unsubmitted text\nUnicode café");
        app.handle_lesson_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        app.handle_lesson_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        let retained = app.router.lessons.form.clone();
        app.reduce_key(KeyEvent::new(KeyCode::Char(action), KeyModifiers::NONE));
        assert_eq!(app.router.lessons.form, retained, "action: {action}");
        assert_eq!(app.editor().input(), "Retained composer");
        assert!(app.runtime_state.lesson_write.is_none());
    }
}

fn app_with_accepted_lesson() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let (workspace, store, _) = fixture::prepare(root.path());
    let finding_id = store.list_all_findings().unwrap()[0].id.unwrap();
    draft_preservation::accepted_lesson(&store, root.path(), finding_id);
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.open_lessons();
    app.router.lessons.finding_id = Some(finding_id);
    app.workbench_cache().borrow_mut().lesson_pages.insert(
        (workspace.root().into(), 0),
        Ok(store.finding_lessons(50, 0).unwrap()),
    );
    (root, app)
}

fn retain_form(app: &mut ShellApp) -> LessonForm {
    app.begin_lesson_draft(false);
    app.paste_lesson_field("Unsubmitted title");
    press(app, KeyCode::Tab);
    app.paste_lesson_field("Unsubmitted text\nUnicode café");
    press(app, KeyCode::Left);
    press(app, KeyCode::Esc);
    app.router.lessons.form.clone().unwrap()
}

fn press(app: &mut ShellApp, code: KeyCode) {
    assert!(
        app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE))
            .handled
    );
}

#[test]
fn resume_and_back_preserve_text_caret_focus_and_composer() {
    let (_root, mut app) = app_with_accepted_lesson();
    app.editor_mut().set_input("Retained composer");
    let retained = retain_form(&mut app);
    press(&mut app, KeyCode::Char('a'));
    assert!(app.router.lessons.replacement_form.is_some());
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.router.lessons.form.as_ref(), Some(&retained));
    assert!(!app.router.lessons.form_visible);
    press(&mut app, KeyCode::Char('e'));
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.router.lessons.form.as_ref(), Some(&retained));
    assert!(app.router.lessons.replacement_form.is_none());
    assert!(app.router.lessons.form_visible);
    assert_eq!(app.editor().input(), "Retained composer");
    assert_eq!(app.shell_view(), ShellView::Lessons);
    assert!(app.runtime_state.lesson_write.is_none());
}

#[test]
fn only_explicit_discard_opens_the_requested_form_without_submitting_it() {
    for action in ['n', 'e', 'a', 'r', 't'] {
        let (_root, mut app) = app_with_accepted_lesson();
        retain_form(&mut app);
        press(&mut app, KeyCode::Char(action));
        let requested = app.router.lessons.replacement_form.clone().unwrap();
        app.reduce_key(KeyEvent::new(KeyCode::Char('D'), KeyModifiers::SHIFT));
        assert_eq!(app.router.lessons.form.as_ref(), Some(&requested));
        assert!(app.router.lessons.replacement_form.is_none());
        assert!(app.router.lessons.form_visible);
        assert!(!app.router.lessons.form.as_ref().unwrap().confirming);
        assert!(app.runtime_state.lesson_write.is_none());
    }
}

#[test]
fn unchanged_or_restored_text_does_not_need_discarding() {
    let (_root, mut app) = app_with_accepted_lesson();
    app.begin_lesson_draft(true);
    assert!(!app
        .router
        .lessons
        .form
        .as_ref()
        .unwrap()
        .has_unsaved_changes());
    press(&mut app, KeyCode::Esc);
    app.begin_lesson_review(LessonState::Accepted);
    assert!(app.router.lessons.replacement_form.is_none());
    app.paste_lesson_field("Temporary reason");
    app.reduce_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    assert!(!app
        .router
        .lessons
        .form
        .as_ref()
        .unwrap()
        .has_unsaved_changes());
    press(&mut app, KeyCode::Esc);
    app.begin_lesson_draft(false);
    assert!(app.router.lessons.replacement_form.is_none());
}

#[test]
fn the_choice_owns_paste_page_keys_and_hidden_action_shortcuts() {
    let (_root, mut app) = app_with_accepted_lesson();
    app.editor_mut().set_input("Retained composer");
    let retained = retain_form(&mut app);
    press(&mut app, KeyCode::Char('t'));
    let requested = app.router.lessons.replacement_form.clone();
    assert!(app.paste_lesson_field("Do not insert into either draft"));
    for code in [
        KeyCode::Char('g'),
        KeyCode::Char('a'),
        KeyCode::Char('n'),
        KeyCode::PageDown,
        KeyCode::Home,
        KeyCode::End,
    ] {
        press(&mut app, code);
    }
    app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT));
    assert_eq!(app.router.lessons.form.as_ref(), Some(&retained));
    assert_eq!(app.router.lessons.replacement_form, requested);
    assert_eq!(app.editor().input(), "Retained composer");
    assert!(app.runtime_state.lesson_write.is_none());
    assert!(!app.lesson_reading_is_active());
}

#[test]
fn the_choice_keeps_safe_and_destructive_controls_visible_at_all_six_sizes() {
    let (_root, mut app) = app_with_accepted_lesson();
    retain_form(&mut app);
    press(&mut app, KeyCode::Char('t'));
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let text = reader::render(&app, width, height);
        for label in [
            "UNFINISHED LESSON",
            "RETIRED LESSON",
            "Enter",
            "resume",
            "Esc",
            "discard/open",
        ] {
            assert!(text.contains(label), "Missing {label} at {width}x{height}");
        }
    }
}
