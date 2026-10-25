use super::*;
use kuzushi_core::findings::FindingStore;

fn book(count: usize) -> (tempfile::TempDir, ShellApp, FindingStore) {
    let root = tempfile::tempdir().unwrap();
    let (workspace, store, _) = fixture::prepare(root.path());
    let id = store.list_all_findings().unwrap()[0].id.unwrap();
    let origin = store.lesson_origin(root.path(), id).unwrap();
    for index in 1..=count {
        store
            .draft_finding_lesson(content(index), origin.clone(), None)
            .unwrap();
    }
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.open_lessons();
    hydrate(&mut app, &store, 0);
    (root, app, store)
}

fn content(index: usize) -> LessonContent {
    LessonContent {
        title: format!("Book lesson {index:03}"),
        text: "Review the labeled historical greeting.".into(),
        applicability: "Owned fixture source review".into(),
        limitations: "No vulnerability claim. Other revisions require review.".into(),
    }
}

fn hydrate(app: &mut ShellApp, store: &FindingStore, offset: usize) {
    app.router.lessons.offset = offset;
    app.workbench_cache().borrow_mut().lesson_pages.insert(
        (app.target_owned().unwrap(), offset),
        Ok(store.finding_lessons(50, offset).unwrap()),
    );
}

fn revise_selected(app: &mut ShellApp) -> FindingLesson {
    let record = app.selected_lesson().unwrap();
    let mut revised = record.content.clone();
    revised.title.push_str(" revised");
    app.spawn_lesson_action(
        "findings:lesson-save",
        serde_json::json!({
            "lessonRef": record.reference().unwrap(), "content": revised
        }),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !app.poll_lesson_write() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    record
}

#[test]
fn own_save_keeps_the_same_lesson_when_latest_order_changes() {
    let (_root, mut app, store) = book(2);
    app.router.lessons.cursor = 1;
    app.editor_mut().set_input("retained composer");
    let before = revise_selected(&mut app);
    hydrate(&mut app, &store, 0);
    let after = app.selected_lesson().unwrap();
    assert_eq!(after.id, before.id);
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(app.editor().input(), "retained composer");
    assert_eq!(app.shell_view(), ShellView::Lessons);
}

#[test]
fn saved_lesson_outside_page_stays_readable_and_is_the_only_review_target() {
    let (_root, mut app, store) = book(60);
    hydrate(&mut app, &store, 50);
    app.router.lessons.cursor = 9;
    let before = revise_selected(&mut app);
    hydrate(&mut app, &store, 50);
    assert_eq!(app.router.lessons.offset, 50);
    assert_eq!(app.selected_lesson().unwrap().id, before.id);
    let screen = reader::render(&app, 120, 36);
    assert!(screen.contains("outside this page"), "{screen}");
    assert!(screen.contains("Book lesson 001 revised"), "{screen}");
    app.begin_lesson_review(LessonState::Accepted);
    let LessonFormAction::Review { record, .. } = &app.router.lessons.form.as_ref().unwrap().action
    else {
        panic!("review form missing")
    };
    assert_eq!(record.id, before.id);
    assert_eq!(record.revision, before.revision + 1);
}

#[test]
fn explicit_refresh_preserves_identity_after_an_external_reorder() {
    let (_root, mut app, store) = book(2);
    app.router.lessons.cursor = 1;
    let before = app.selected_lesson().unwrap();
    store
        .revise_finding_lesson(&before.reference().unwrap(), content(3))
        .unwrap();
    app.refresh_lessons();
    hydrate(&mut app, &store, 0);
    assert_eq!(app.selected_lesson().unwrap().id, before.id);
}

#[test]
fn compact_lesson_help_keeps_selection_paging_and_refresh_discoverable() {
    let (_root, mut app, _) = book(1);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let bindings = crate::ui_view_models::footer_keybindings(&app);
        for expected in ["Space", "[/]", "R"] {
            assert!(
                bindings.iter().any(|binding| binding.key == expected),
                "{expected} missing at {width}x{height}: {bindings:?}"
            );
        }
    }
}

#[test]
fn a_late_cached_page_cannot_replace_a_newer_saved_revision() {
    let (_root, mut app, store) = book(2);
    app.router.lessons.cursor = 1;
    let old_page = store.finding_lessons(50, 0).unwrap();
    let before = revise_selected(&mut app);
    app.workbench_cache()
        .borrow_mut()
        .lesson_pages
        .insert((app.target_owned().unwrap(), 0), Ok(old_page));
    assert_eq!(app.selected_lesson().unwrap().revision, before.revision + 1);
    let screen = reader::render(&app, 120, 36);
    assert!(
        screen.contains("Recorded revision newer than this page"),
        "{screen}"
    );
    assert!(screen.contains("Book lesson 001 revised"), "{screen}");
}

#[test]
fn an_off_page_receipt_names_the_target_before_actions_in_a_compact_frame() {
    let (_root, mut app, store) = book(60);
    hydrate(&mut app, &store, 50);
    app.router.lessons.cursor = 9;
    revise_selected(&mut app);
    hydrate(&mut app, &store, 50);
    app.set_viewport(crate::TerminalViewport::new(40, 12));
    let screen = reader::render(&app, 40, 12);
    assert!(screen.contains("Book lesson 001 revised"), "{screen}");
    assert!(screen.contains("Draft"), "{screen}");
}

#[test]
fn moving_from_a_recorded_selection_explicitly_chooses_the_first_visible_row() {
    let (_root, mut app, store) = book(60);
    hydrate(&mut app, &store, 50);
    app.router.lessons.cursor = 9;
    revise_selected(&mut app);
    hydrate(&mut app, &store, 50);
    let first = store.finding_lessons(50, 50).unwrap().rows[0].id.clone();
    app.handle_lesson_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    assert_eq!(app.selected_lesson().unwrap().id, first);
    assert_eq!(app.router.lessons.cursor, 0);
}

#[test]
fn a_late_empty_page_keeps_the_saved_receipt_instead_of_claiming_no_lessons() {
    let (_root, mut app, _store) = book(1);
    let before = revise_selected(&mut app);
    app.workbench_cache().borrow_mut().lesson_pages.insert(
        (app.target_owned().unwrap(), 0),
        Ok(FindingLessonPage {
            rows: Vec::new(),
            offset: 0,
            has_more: false,
        }),
    );
    assert_eq!(app.selected_lesson().unwrap().revision, before.revision + 1);
    let screen = reader::render(&app, 120, 36);
    assert!(screen.contains("Book lesson 001 revised"), "{screen}");
    assert!(!screen.contains("No saved lessons"), "{screen}");
}

#[test]
fn malformed_or_mismatched_write_receipts_retain_the_form_and_exact_selection() {
    let (_root, mut app, store) = book(1);
    let record = app.selected_lesson().unwrap();
    app.begin_lesson_draft(true);
    app.paste_lesson_field(" retained edit");
    let form = app.router.lessons.form.clone();
    let mut wrong_reference = record.reference().unwrap();
    wrong_reference.sha256 = format!("sha256:{}", "0".repeat(64));
    for output in [
        serde_json::json!({"ok":true,"data":{}}),
        serde_json::json!({"ok":true,"data":{"lesson":record,"lessonRef":wrong_reference}}),
    ] {
        app.runtime_state.lesson_write = Some(LessonWrite {
            target: app.target_owned().unwrap(),
            action: "findings:lesson-save",
            handle: std::thread::spawn(move || Ok(output)),
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !app.poll_lesson_write() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert_eq!(app.router.lessons.form, form);
        assert!(app.router.lessons.form_visible);
        assert_eq!(app.selected_lesson().unwrap(), record);
        assert!(app
            .router
            .lessons
            .notice
            .as_ref()
            .unwrap()
            .contains("receipt is not confirmed"));
    }
    assert_eq!(store.finding_lesson(&record.id).unwrap().unwrap(), record);
}

#[test]
fn review_confirmation_names_the_exact_lesson_before_commit_controls() {
    let (_root, mut app, _store) = book(1);
    app.begin_lesson_review(LessonState::Accepted);
    app.paste_lesson_field("Reviewed the exact labeled lesson.");
    app.handle_lesson_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    let screen = reader::render(&app, 120, 36);
    let identity = screen
        .find("Book lesson 001")
        .expect("lesson title is missing");
    let controls = screen
        .find("Enter records this action")
        .expect("controls are missing");
    assert!(identity < controls, "{screen}");
    assert!(screen.contains("v1"), "{screen}");
    assert!(app.runtime_state.lesson_write.is_none());
}

#[test]
#[ignore = "fixture writer requires an explicitly supplied owned directory"]
fn prepare_native_lesson_book_fixture() {
    let root = PathBuf::from(
        std::env::var_os("KUZUSHI_LESSON_BOOK_FIXTURE_OUT")
            .expect("owned fixture directory is required"),
    );
    let (workspace, store, base) = fixture::prepare(&root);
    let finding_id = store.list_all_findings().unwrap()[0].id.unwrap();
    let config = kuzushi_core::V2Config::default();
    let mut primary = None;
    for index in 1..=60 {
        let saved = kuzushi_core::workspace::execute_lesson_action(
            &workspace,
            &config,
            "findings:lesson-save",
            serde_json::json!({"findingId": finding_id, "content":content(index)}),
        )
        .unwrap();
        if index == 1 {
            primary = Some(kuzushi_core::workspace::execute_lesson_action(&workspace, &config,
                "findings:lesson-review", serde_json::json!({"lessonRef":saved["data"]["lessonRef"],
                    "state":"accepted", "note":"Fixture operator accepts only labeled historical greeting guidance."})).unwrap()["data"].clone());
        }
    }
    let receipt = serde_json::json!({"findingId":finding_id,"baseRef":base,"primary":primary,
        "findingsAreSynthetic":true,"providerRequests":0,"sourceExecuted":false});
    std::fs::write(
        workspace.root().join(".kuzushi/lesson-book-fixture.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
}
