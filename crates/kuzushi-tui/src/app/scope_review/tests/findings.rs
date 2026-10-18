use super::*;

fn accept(app: &mut ShellApp, root: &std::path::Path) {
    app.open_scope_acceptance();
    press(app, KeyCode::Enter);
    press(app, KeyCode::End);
    let update = press(app, KeyCode::Enter);
    finish(app, root, update).unwrap();
}

#[test]
fn scope_findings_restores_the_exact_boundary_draft_filter_and_selected_study() {
    let (root, mut app) = fixture();
    accept(&mut app, root.path());
    app.set_input("Held scope draft\nsecond line");
    app.set_cursor(5);
    app.set_active_findings_filter(Some("rank:critical".into()));
    app.router.campaign_mut().active_batch_id = Some("previous-study".into());
    let state = app.router.scope_review_mut().as_mut().unwrap();
    state.scroll = 7;
    let reference = state.review.as_ref().unwrap().reference.clone();
    let workbench = app.router.workbench().clone();
    let update = press(&mut app, KeyCode::Char('v'));
    let query = update
        .effects
        .iter()
        .find_map(|effect| match effect {
            ShellEffect::RefreshFindings(request) => request.filter.as_deref(),
            _ => None,
        })
        .expect("Scope navigation must use the shared query effect");
    let filter = kuzushi_core::FindingListFilter::from_filter_expression(query).unwrap();
    assert_eq!(filter.scope_id, ["repository"]);
    assert_eq!(filter.scope_record, [reference.record_hash]);
    assert!(!app.scope_review_is_visible());
    assert!(app.scope_findings_return_is_available());
    assert!(
        app.router.campaign().active_batch_id.is_none(),
        "A scope reader spans saved studies"
    );
    assert!(!update
        .effects
        .iter()
        .any(|effect| matches!(effect, ShellEffect::PrepareRunTool(_))));
    app.go_back();
    assert!(app.scope_review_is_visible());
    assert_eq!(app.scope_review().unwrap().scroll, 7);
    assert_eq!(app.router.workbench(), &workbench);
    assert_eq!(
        app.active_findings_filter().as_deref(),
        Some("rank:critical")
    );
    assert_eq!(
        app.router.campaign().active_batch_id.as_deref(),
        Some("previous-study")
    );
    assert_eq!(
        (app.input(), app.cursor()),
        ("Held scope draft\nsecond line", 5)
    );
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn drafts_and_file_readers_cannot_trigger_the_hidden_scope_findings_shortcut() {
    let (root, mut app) = fixture();
    assert!(press(&mut app, KeyCode::Char('v')).effects.is_empty());
    assert!(app.scope_review_is_visible());
    assert!(app
        .scope_review()
        .unwrap()
        .notice
        .as_deref()
        .unwrap()
        .contains("Accept boundaries"));
    accept(&mut app, root.path());
    let files = press(&mut app, KeyCode::Char('f'));
    finish(&mut app, root.path(), files).unwrap();
    assert!(press(&mut app, KeyCode::Char('v')).effects.is_empty());
    assert!(app.scope_review_is_visible());
    assert!(app.scope_review().unwrap().findings_origin.is_none());
    assert!(app
        .scope_review()
        .unwrap()
        .notice
        .as_deref()
        .unwrap()
        .contains("Return from the file reader"));
}

#[test]
fn changing_target_does_not_restore_an_old_scope_reader() {
    let (root, mut app) = fixture();
    accept(&mut app, root.path());
    press(&mut app, KeyCode::Char('v'));
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().into()));
    assert!(!app.restore_scope_findings_origin());
    assert!(!app.scope_findings_return_is_available());
}

#[test]
fn saved_findings_action_retains_its_menu_search_when_returning() {
    let (root, mut app) = fixture();
    accept(&mut app, root.path());
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('/'));
    assert!(app.capture_scope_review_paste("View saved findings"));
    let before = app.scope_review().unwrap().menu_search.clone();
    press(&mut app, KeyCode::Enter);
    assert!(app.scope_findings_return_is_available());
    app.go_back();
    assert!(app.scope_review_is_visible());
    assert_eq!(app.scope_review().unwrap().menu, Some(16));
    assert_eq!(app.scope_review().unwrap().menu_search, before);
}

#[test]
fn saved_findings_action_explains_reading_and_keeps_back_visible_at_every_size() {
    let (root, mut app) = fixture();
    accept(&mut app, root.path());
    app.router.scope_review_mut().as_mut().unwrap().menu = Some(16);
    let detail =
        crate::ui_view_models::scope_review::scope_detail(app.scope_review().unwrap()).join("\n");
    assert!(detail.contains("Saved findings for"));
    assert!(detail.contains("No discovery or model work starts"));
    assert!(!detail.contains("Create a separate inventory"));
    app.open_selected_scope_findings();
    *app.findings_mut() = vec![kuzushi_core::Finding::new_semgrep(
        "owned.scope",
        "src/app.rs",
        1,
        Some(1),
        kuzushi_core::Severity::High,
        "Owned scope observation",
    )];
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::render_app(frame, &app))
            .unwrap();
        let screen = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(screen.contains("q scopes"), "{width}x{height}: {screen}");
    }
}
