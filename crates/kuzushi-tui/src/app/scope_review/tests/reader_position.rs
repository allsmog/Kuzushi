use super::*;
use unicode_width::UnicodeWidthStr;

fn header(app: &ShellApp, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| crate::render_app(frame, app))
        .unwrap();
    let buffer = terminal.backend().buffer();
    let mut text = String::new();
    let mut column = 0;
    while column < width {
        let symbol = buffer[(column, 1)].symbol();
        text.push_str(symbol);
        column += symbol.width().max(1) as u16;
    }
    text.trim().trim_matches('│').trim().to_string()
}

#[test]
fn pinned_boundary_and_visible_line_range_follow_paging_and_resize_without_taking_rows() {
    let (root, mut app) = fixture();
    split(&mut app, root.path());
    app.reduce_resize(40, 12);
    app.set_input("preserved draft");
    app.set_cursor(5);
    press(&mut app, KeyCode::Tab);
    assert!(header(&app, 40, 12).starts_with("Auth · 1-6/"));
    press(&mut app, KeyCode::PageDown);
    assert!(header(&app, 40, 12).starts_with("Auth · 7-12/"));
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        app.reduce_resize(width, height);
        press(&mut app, KeyCode::End);
        let state = app.scope_review().unwrap();
        let area = crate::ui_view_models::study_config::study_config_area(width, height);
        let layout = crate::ui_view_models::scope_review::scope_review_layout(area, state);
        let total = crate::ui_view_models::scope_review::scope_detail_lines(
            &app,
            state,
            &crate::ui_view_models::scope_review::scope_source_view(&app, state),
            layout.detail.width as usize,
        )
        .len();
        assert_eq!(layout.detail.height, height - 6);
        let text = header(&app, width, height);
        assert!(text.starts_with("Auth · "), "{width}x{height}: {text}");
        assert!(text.ends_with(&format!("-{total}/{total}")), "{text}");
    }
    press(&mut app, KeyCode::Esc);
    assert!(header(&app, 40, 12).starts_with("Repository:"));
    assert_eq!((app.input(), app.cursor()), ("preserved draft", 5));
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn file_and_coverage_readers_keep_their_own_identity_at_the_document_end() {
    let (root, mut app) = fixture();
    split(&mut app, root.path());
    app.reduce_resize(40, 12);
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::End);
    assert!(header(&app, 40, 12).starts_with("File: auth/login.rs · "));
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Left);
    press(&mut app, KeyCode::Left);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::End);
    assert!(header(&app, 40, 12).starts_with("Uncovered files · "));
    assert!(!app.has_running_work());
}

#[test]
fn exhaustive_plain_reader_retains_the_repository_and_full_subject() {
    let (root, mut app) = fixture();
    split(&mut app, root.path());
    let state = app.router.scope_review_mut().as_mut().unwrap();
    std::sync::Arc::make_mut(state.review.as_mut().unwrap())
        .record
        .draft
        .scopes[0]
        .name = "認証 service with a deliberately long boundary label".into();
    app.reduce_resize(40, 12);
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::End);
    let captured = header(&app, 40, 12);
    assert!(captured.starts_with("認証 service"), "{captured:?}");
    let plain = crate::renderer::render_plain_app(&app, 160);
    assert!(plain.contains(&format!("Repository: {}", root.path().display())));
    assert!(plain.contains("認証 service with a deliberately long boundary label"));
    assert!(plain.contains("Source snapshot:"));
}
