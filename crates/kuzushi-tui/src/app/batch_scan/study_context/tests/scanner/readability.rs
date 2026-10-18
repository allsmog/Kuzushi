use super::*;

fn readable_context() -> (tempfile::TempDir, ShellApp, ThreatModelRef, ThreatModelRef) {
    let (root, mut app, first, active) = fixture();
    app.handle_study_context_key(KeyCode::Up);
    let mut result = inspect(&app, root.path(), &first);
    let text = "Modeled threats:\n- Keep invoice visibility scoped to its owner.";
    result["data"]["scannerContextPreview"]["text"] = json!(text);
    result["data"]["scannerContextPreview"]["sha256"] =
        json!(kuzushi_core::prompt_content_sha256(text));
    app.cache_tool_snapshot("threat-model:read", &result);
    app.set_input("retained context draft");
    app.set_cursor(7);
    app.handle_study_context_key(KeyCode::Char('p'));
    (root, app, first, active)
}

fn frame_text(app: &ShellApp, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    format!("{:?}", terminal.backend().buffer())
}

#[test]
fn first_scanner_frame_shows_selected_context_and_request_bytes_at_every_size() {
    let (_root, mut app, first, _) = readable_context();
    for (width, height) in [(40, 11), (60, 19), (80, 23), (96, 88), (120, 35), (160, 47)] {
        app.reduce_resize(width, height);
        app.handle_study_context_key(KeyCode::Home);
        let text = frame_text(&app, width, height);
        assert!(
            text.contains("Context: First context"),
            "{width}x{height}: {text}"
        );
        assert!(
            text.contains("- Keep invoice visibility"),
            "{width}x{height}: {text}"
        );
        assert!(!text.contains("Omit threat-model context"));
        assert_eq!(
            app.study_context_picker().unwrap().selected.as_ref(),
            Some(&first)
        );
    }
}

#[test]
fn reader_pages_reach_details_and_return_without_editing_context_plan_or_draft() {
    let (root, mut app, first, active) = readable_context();
    let original = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .clone();
    app.reduce_resize(40, 11);
    let mut seen = String::new();
    loop {
        seen.push_str(&frame_text(&app, 40, 11));
        let before = app.study_context_picker().unwrap().detail_scroll;
        app.handle_study_context_key(KeyCode::PageDown);
        if app.study_context_picker().unwrap().detail_scroll == before {
            break;
        }
    }
    assert!(seen.contains("CONTEXT DETAILS AND LIMITS"));
    assert!(seen.contains("Digest text hash:"));
    assert!(seen.contains("Document hash:"));
    app.handle_study_context_key(KeyCode::Home);
    assert!(frame_text(&app, 40, 11).contains("- Keep invoice visibility"));
    assert_eq!(
        app.study_context_picker().unwrap().selected.as_ref(),
        Some(&first)
    );
    app.handle_study_context_key(KeyCode::Tab);
    assert_eq!(
        app.study_context_picker().unwrap().text_view,
        StudyContextTextView::Document
    );
    app.handle_study_context_key(KeyCode::Esc);
    assert!(app.study_context_picker().is_none());
    assert_eq!((app.input(), app.cursor()), ("retained context draft", 7));
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study,
        original
    );
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        active
    );
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}
