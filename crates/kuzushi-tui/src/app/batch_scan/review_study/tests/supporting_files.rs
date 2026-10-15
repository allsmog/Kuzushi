use super::*;

fn cited_fixture() -> (tempfile::TempDir, ShellApp) {
    let (root, mut app) = fixture();
    app.handle_review_study_key(KeyCode::Char('s'));
    app.handle_review_study_key(KeyCode::Char('s'));
    app.handle_review_study_key(KeyCode::Char('e'));
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .review_plan
        .as_mut()
        .unwrap()
        .input["sourceEvidenceRef"] = json!("prior-ref");
    (root, app)
}

fn press(app: &mut ShellApp, code: KeyCode) {
    let update = app.handle_file_picker_key(KeyEvent::new(code, KeyModifiers::NONE));
    assert!(update.effects.is_empty());
}

fn choose(app: &mut ShellApp, path: &str) {
    app.router.file_picker_mut().paste_query(path);
    press(app, KeyCode::Char(' '));
}

fn input(app: &ShellApp) -> Value {
    app.router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .review_plan
        .as_ref()
        .unwrap()
        .input
        .clone()
}

#[test]
fn review_supporting_picker_cancels_or_applies_without_starting_work() {
    let (_root, mut app) = cited_fixture();
    let before = input(&app);
    let origin = app.shell_view();
    app.handle_review_study_key(KeyCode::Char('f'));
    assert_eq!(app.shell_view(), ShellView::FilePicker);
    choose(&mut app, "service.txt");
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), origin);
    assert_eq!(input(&app), before);
    app.handle_review_study_key(KeyCode::Char('f'));
    choose(&mut app, "store.txt");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.shell_view(), origin);
    assert_eq!(input(&app)["sourceEvidenceFiles"], json!(["store.txt"]));
    assert!(input(&app).get("sourceEvidenceRef").is_none());
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(config.study.allowance.is_none());
    assert!(!app.has_running_work());
}

#[test]
fn review_supporting_picker_keeps_ref_when_selection_did_not_change() {
    let (_root, mut app) = cited_fixture();
    let before = input(&app);
    app.handle_review_study_key(KeyCode::Char('f'));
    press(&mut app, KeyCode::Enter);
    assert_eq!(input(&app), before);
    app.handle_review_study_key(KeyCode::Char('e'));
    assert!(input(&app).get("sourceEvidenceFiles").is_none());
    assert!(input(&app).get("sourceEvidenceRef").is_none());
}

#[test]
fn review_supporting_picker_restores_queries_and_survives_index_refresh() {
    let (_root, mut app) = cited_fixture();
    app.handle_review_study_key(KeyCode::Char('f'));
    choose(&mut app, "service.txt");
    press(&mut app, KeyCode::Left);
    let query = app.router.file_picker().query_field().clone();
    press(&mut app, KeyCode::Tab);
    assert!(app.router.file_picker().review_selection().basket());
    assert_eq!(app.router.file_picker().filtered_paths(), ["service.txt"]);
    app.router
        .file_picker_mut()
        .replace_files(vec!["other.txt".into()], true);
    assert_eq!(app.router.file_picker().filtered_paths(), ["service.txt"]);
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.router.file_picker().query_field(), &query);
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Char(' '));
    assert!(app
        .router
        .file_picker()
        .review_selection()
        .paths()
        .is_empty());
    assert_eq!(app.router.file_picker().cursor(), 0);
}

#[test]
fn review_supporting_picker_discloses_cap_and_retains_exact_choices() {
    let (_root, mut app) = cited_fixture();
    app.handle_review_study_key(KeyCode::Char('f'));
    for index in 0..17 {
        app.router
            .file_picker_mut()
            .edit_query(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        choose(&mut app, &format!("file{index}.txt"));
    }
    assert_eq!(
        app.router.file_picker().review_selection().paths().len(),
        16
    );
    assert!(app
        .router
        .file_picker()
        .review_selection()
        .notice()
        .unwrap()
        .contains("at most 16"));
    assert!(!app.has_running_work());
}

#[test]
fn review_supporting_picker_controls_remain_visible_at_every_viewport() {
    let (_root, mut app) = cited_fixture();
    app.handle_review_study_key(KeyCode::Char('f'));
    choose(&mut app, "store.txt");
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let screen = terminal
            .backend()
            .buffer()
            .content
            .chunks(width as usize)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        for label in [
            "REVIEW SUPPORTING FILES",
            "1/16",
            "Space toggle",
            "Tab basket",
            "Enter apply",
            "Esc cancel",
        ] {
            assert!(
                screen.contains(label),
                "{width}x{height}: {label}\n{screen}"
            );
        }
        let plain = crate::renderer::render_plain_app(&app, width as usize);
        assert!(plain.contains("store.txt"), "{plain}");
        assert!(!plain.contains('\u{1b}'));
    }
}

#[test]
fn review_supporting_picker_requires_explicit_standard_and_cited_choices() {
    let (_root, mut app) = fixture();
    let before = input(&app);
    app.handle_review_study_key(KeyCode::Char('f'));
    assert_eq!(input(&app), before);
    assert_ne!(app.shell_view(), ShellView::FilePicker);
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .notice
        .as_deref()
        .unwrap()
        .contains("Use s"));
}
