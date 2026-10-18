use super::*;

#[test]
fn enumeration_and_content_limits_are_readable_and_acknowledgement_is_still_required() {
    let (root, mut app) = fixture();
    std::fs::write(
        root.path().join("large.rs"),
        b"// inert prefix\n".repeat(18000),
    )
    .unwrap();
    let update = press(&mut app, KeyCode::Char('c'));
    finish(&mut app, root.path(), update).unwrap();
    app.set_input("preserve this draft");
    app.set_cursor(4);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        app.router.scope_review_mut().as_mut().unwrap().scroll = 0;
        let mut observed = String::new();
        for _ in 0..24 {
            observed.push_str(&draw(&app));
            assert!(press(&mut app, KeyCode::PageDown).effects.is_empty());
        }
        assert!(
            observed.contains("File enumeration:"),
            "{width}x{height}: {observed}"
        );
        assert!(
            observed.contains("inventory policy"),
            "{width}x{height}: {observed}"
        );
    }
    press(&mut app, KeyCode::Char('a'));
    press(&mut app, KeyCode::End);
    let update = press(&mut app, KeyCode::Enter);
    let error = finish(&mut app, root.path(), update).unwrap_err();
    assert!(error.to_string().contains("inventory limitations"));
    app.scope_review_failed("pack:scopes", &error.to_string());
    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::End);
    let update = press(&mut app, KeyCode::Enter);
    finish(&mut app, root.path(), update).unwrap();
    assert!(app
        .scope_review()
        .unwrap()
        .review
        .as_ref()
        .unwrap()
        .record
        .acceptance
        .is_some());
    assert_eq!((app.input(), app.cursor()), ("preserve this draft", 4));
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

fn draw(app: &ShellApp) -> String {
    let viewport = app.viewport();
    let mut terminal = Terminal::new(TestBackend::new(viewport.columns, viewport.rows)).unwrap();
    terminal
        .draw(|frame| crate::render_app(frame, app))
        .unwrap();
    terminal
        .backend()
        .buffer()
        .content()
        .chunks(usize::from(viewport.columns))
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}
