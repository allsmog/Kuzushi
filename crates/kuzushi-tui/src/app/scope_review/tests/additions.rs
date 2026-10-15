use super::*;

fn uncovered_fixture() -> (tempfile::TempDir, ShellApp) {
    let (root, mut app) = fixture();
    let scope = kuzushi_core::workspace::ProposedScanScope {
        id: "app".into(),
        name: "App".into(),
        paths: vec!["auth".into()],
        rationale: "Owned application source.".into(),
        shared_dependencies: Vec::new(),
        open_questions: Vec::new(),
    };
    let update = app.dispatch_scope_request(json!({"operation":"create", "draft":{
        "schemaVersion":1,"scopes":[scope],"sharedScope":null,"sharedDiscovery":false,"exclusions":[]}}));
    finish(&mut app, root.path(), update).unwrap();
    (root, app)
}

#[test]
fn addition_uses_shared_dispatch_and_leaves_work_and_acceptance_separate() {
    let (root, mut app) = uncovered_fixture();
    let before = app.scope_review().unwrap().review.as_ref().unwrap().clone();
    app.apply_scope_menu(15);
    let form = app.scope_review().unwrap().form.as_ref().unwrap();
    assert_eq!(form.fields[1].1.text(), "README.md");
    fill_form(
        &mut app,
        &[
            "Root material",
            "README.md",
            "Explicit loose root discovery.",
        ],
    );
    let update = press(&mut app, KeyCode::F(2));
    finish(&mut app, root.path(), update).unwrap();
    let after = app.scope_review().unwrap().review.as_ref().unwrap();
    assert_eq!(after.coverage.uncovered_files.total, 0);
    assert_eq!(after.coverage.overlaps.total, 0);
    assert_eq!(after.record.draft.scopes.len(), 2);
    assert!(after.record.acceptance.is_none());
    assert_eq!(after.record.previous.as_ref(), Some(&before.reference));
    assert_eq!(
        selected_scope(app.scope_review().unwrap()).unwrap().name,
        "Root material"
    );
    assert_eq!(app.scope_review().unwrap().scroll, 0);
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
    assert!(app.findings().is_empty());
}

#[test]
fn invalid_addition_and_back_keep_fields_cursor_and_private_quit_warning() {
    let (root, mut app) = uncovered_fixture();
    let before = app
        .scope_review()
        .unwrap()
        .review
        .as_ref()
        .unwrap()
        .reference
        .clone();
    app.apply_scope_menu(15);
    fill_form(
        &mut app,
        &["private operator draft", "../outside", "Owned rationale"],
    );
    app.router
        .scope_review_mut()
        .as_mut()
        .unwrap()
        .form
        .as_mut()
        .unwrap()
        .cursor = 1;
    let update = press(&mut app, KeyCode::F(2));
    assert!(finish(&mut app, root.path(), update).is_err());
    app.scope_review_failed("pack:scopes", "Invalid path");
    assert_eq!(
        app.scope_review()
            .unwrap()
            .review
            .as_ref()
            .unwrap()
            .reference,
        before
    );
    let kept = app.scope_review().unwrap().form.as_ref().unwrap().clone();
    press(&mut app, KeyCode::Esc);
    let warning = crate::ui_view_models::quit_confirm_model(&app);
    let text = warning
        .sections
        .iter()
        .flat_map(|section| section.rows.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(text.contains("scope draft") && !text.contains("private operator draft"));
    app.apply_scope_menu(15);
    assert_eq!(app.scope_review().unwrap().form.as_ref(), Some(&kept));
}

#[test]
fn incomplete_or_large_previews_never_prefill_a_partial_membership_list() {
    let (_root, mut app) = uncovered_fixture();
    for total in [33, 200] {
        let mut review = app
            .scope_review()
            .unwrap()
            .review
            .as_ref()
            .unwrap()
            .as_ref()
            .clone();
        review.coverage.uncovered_files.total = total;
        review.coverage.uncovered_files.files = vec!["README.md".into(); 32];
        app.router
            .scope_review_mut()
            .as_mut()
            .unwrap()
            .install(review);
        app.apply_scope_menu(15);
        assert!(app.scope_review().unwrap().form.as_ref().unwrap().fields[1]
            .1
            .text()
            .is_empty());
        app.router.scope_review_mut().as_mut().unwrap().form = None;
    }
}

#[test]
fn new_scope_paths_preserve_literal_whitespace() {
    let (_root, mut app) = uncovered_fixture();
    app.apply_scope_menu(15);
    fill_form(
        &mut app,
        &["Literal", " space.rs \napp/[slug]", "Exact paths"],
    );
    let form = app.scope_review().unwrap().form.as_ref().unwrap();
    let kuzushi_core::workspace::ScanScopeEdit::AddScope { scope } = form.edit(3).unwrap() else {
        panic!("expected addition")
    };
    assert_eq!(scope.paths, vec![" space.rs ", "app/[slug]"]);
}

#[test]
fn every_addition_field_and_its_controls_render_at_required_viewports() {
    let (_root, mut app) = uncovered_fixture();
    app.apply_scope_menu(15);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        for field in 0..3 {
            app.router
                .scope_review_mut()
                .as_mut()
                .unwrap()
                .form
                .as_mut()
                .unwrap()
                .cursor = field;
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| crate::render_app(frame, &app))
                .unwrap();
            let text = format!("{:?}", terminal.backend().buffer());
            assert!(
                text.contains("ADD DISCOVERY SCOPE"),
                "{width}x{height}: {text}"
            );
            assert!(text.contains(&format!("Field {}/3", field + 1)));
            assert!(text.contains("F2 save") && text.contains("Esc cancel edit"));
        }
    }
}
