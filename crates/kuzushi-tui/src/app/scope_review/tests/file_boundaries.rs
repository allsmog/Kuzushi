use super::*;

fn wide_scope() -> (tempfile::TempDir, ShellApp) {
    let (root, mut app) = fixture();
    for index in 0..94 {
        std::fs::write(
            root.path().join(format!("f{index:03}.rs")),
            "// Owned inert source\n",
        )
        .unwrap();
    }
    std::fs::write(root.path().join("z-last.rs"), "// Owned final member\n").unwrap();
    let update = press(&mut app, KeyCode::Char('c'));
    finish(&mut app, root.path(), update).unwrap();
    let update = press(&mut app, KeyCode::Char('f'));
    finish(&mut app, root.path(), update).unwrap();
    (root, app)
}

#[test]
fn first_and_last_file_pages_preserve_scope_revision_and_composer_at_every_size() {
    let (root, mut app) = wide_scope();
    app.set_input("kept private scope draft");
    app.set_cursor(7);
    let reference = app
        .scope_review()
        .unwrap()
        .review
        .as_ref()
        .unwrap()
        .reference
        .clone();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        let update = press(&mut app, KeyCode::End);
        finish(&mut app, root.path(), update).unwrap();
        let state = app.scope_review().unwrap();
        let page = &state.files.as_ref().unwrap().page;
        assert_eq!(page.total, 97);
        assert_eq!(page.offset, 96);
        assert_eq!(page.files, vec!["z-last.rs"]);
        assert_eq!(state.cursor, 0);
        assert_eq!(state.review.as_ref().unwrap().reference, reference);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::render_app(frame, &app))
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(text.contains("Home/End first/last"));
        let update = press(&mut app, KeyCode::Home);
        finish(&mut app, root.path(), update).unwrap();
        assert_eq!(
            app.scope_review()
                .unwrap()
                .files
                .as_ref()
                .unwrap()
                .page
                .offset,
            0
        );
        assert_eq!((app.input(), app.cursor()), ("kept private scope draft", 7));
    }
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn menu_and_acceptance_own_home_and_end_before_the_file_reader() {
    let (_root, mut app) = wide_scope();
    press(&mut app, KeyCode::Enter);
    assert!(press(&mut app, KeyCode::End).effects.is_empty());
    assert_eq!(
        app.scope_review().unwrap().menu,
        Some(SCOPE_ACTIONS.len() - 1)
    );
    press(&mut app, KeyCode::Esc);
    app.open_scope_acceptance();
    assert!(press(&mut app, KeyCode::End).effects.is_empty());
    assert_eq!(app.scope_review().unwrap().acknowledgement_cursor, 3);
    assert_eq!(
        app.scope_review()
            .unwrap()
            .files
            .as_ref()
            .unwrap()
            .page
            .offset,
        0
    );
}
