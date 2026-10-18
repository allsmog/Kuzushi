use super::*;

#[test]
fn saving_a_separate_context_copy_preserves_the_retained_lesson_form() {
    let root = tempfile::tempdir().unwrap();
    let (workspace, store, base) = fixture::prepare(root.path());
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.open_lessons();
    app.router.lessons.finding_id = store.list_all_findings().unwrap()[0].id;
    app.editor_mut().set_input("Retained composer");
    app.begin_lesson_draft(false);
    app.router.lessons.form.as_mut().unwrap().focused = 1;
    app.paste_lesson_field("Unsaved lesson\nUnicode café");
    app.handle_lesson_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    app.handle_lesson_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    let retained = app.router.lessons.form.clone();
    app.spawn_lesson_action(
        "threat-model:reuse-lessons",
        serde_json::json!({"threatModelRef":base,"lessons":[]}),
    );
    finish_write(&mut app);
    assert!(app.router.lessons.saved_context.is_some());
    assert_eq!(app.router.lessons.form, retained);
    assert!(!app.router.lessons.form_visible);
    assert_eq!(app.editor().input(), "Retained composer");
    assert_eq!(app.shell_view(), ShellView::Lessons);
    app.handle_lesson_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
    assert!(app.router.lessons.form_visible);
    assert_eq!(app.router.lessons.form, retained);
}

fn finish_write(app: &mut ShellApp) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !app.poll_lesson_write() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
}

#[test]
fn a_retired_selected_revision_blocks_the_copy_and_keeps_the_draft() {
    let root = tempfile::tempdir().unwrap();
    let (workspace, store, base) = fixture::prepare(root.path());
    let finding_id = store.list_all_findings().unwrap()[0].id.unwrap();
    let accepted = accepted_lesson(&store, root.path(), finding_id);
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.open_lessons();
    app.router.lessons.finding_id = Some(finding_id);
    app.begin_lesson_draft(false);
    app.paste_lesson_field("Keep this unsaved note");
    app.handle_lesson_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    let retained = app.router.lessons.form.clone();
    app.router.lessons.selected = vec![SelectedLesson {
        reference: accepted.reference().unwrap(),
        title: accepted.content.title.clone(),
    }];
    app.router.lessons.context_selecting = true;
    app.router.lessons.context_confirm = Some(LessonContextBase {
        reference: base,
        label: "Owned lesson context".into(),
    });
    store
        .review_finding_lesson(
            &accepted.reference().unwrap(),
            LessonState::Retired,
            "Retired after selection".into(),
        )
        .unwrap();
    app.handle_lesson_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    finish_write(&mut app);
    assert!(app.router.lessons.saved_context.is_none());
    assert_eq!(app.router.lessons.form, retained);
    assert!(app.router.lessons.context_selecting);
    assert!(app
        .router
        .lessons
        .notice
        .as_ref()
        .unwrap()
        .contains("not confirmed"));
    assert_eq!(
        store.finding_lessons(50, 0).unwrap().rows[0].state,
        LessonState::Retired
    );
}

fn accepted_lesson(
    store: &kuzushi_core::FindingStore,
    target: &std::path::Path,
    finding_id: i64,
) -> FindingLesson {
    let draft = store
        .draft_finding_lesson(
            LessonContent {
                title: "Reviewed greeting lesson".into(),
                text: "Inspect the supplied source evidence.".into(),
                applicability: "Owned fixture source review".into(),
                limitations: "Historical guidance only".into(),
            },
            store.lesson_origin(target, finding_id).unwrap(),
            None,
        )
        .unwrap();
    store
        .review_finding_lesson(
            &draft.reference().unwrap(),
            LessonState::Accepted,
            "Reviewed the source and limits".into(),
        )
        .unwrap()
}
