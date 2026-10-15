use super::*;
use crate::app::StudyContextTextView;

#[test]
fn inspection_binds_saved_scanner_bytes_only_to_the_matching_context() {
    let (_root, mut app, first, active) = fixture();
    let frozen = json!({"schemaVersion":1,"object":{"hash":"synthetic-reference"}});
    let picker = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .context_picker
        .as_mut()
        .unwrap();
    picker.scan_input["threatModelRef"] = json!(first);
    picker.scan_input["threatModelDigestRef"] = frozen.clone();
    assert_eq!(
        app.study_context_inspection_input(&first)["threatModelDigestRef"],
        frozen
    );
    assert!(app
        .study_context_inspection_input(&active)
        .get("threatModelDigestRef")
        .is_none());
    app.set_input("retained draft");
    app.set_cursor(5);
    assert_eq!(
        app.study_context_inspection_input(&first)["threatModelRef"],
        json!(first)
    );
    assert_eq!((app.input(), app.cursor()), ("retained draft", 5));
}

#[test]
fn scanner_context_view_uses_the_read_receipt_and_preserves_study_and_composer() {
    let (root, mut app, first, active) = fixture();
    app.handle_study_context_key(KeyCode::Up);
    let result = inspect(&app, root.path(), &first);
    app.cache_tool_snapshot("threat-model:read", &result);
    let original = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .clone();
    app.set_input("retained composer");
    app.set_cursor(4);
    app.handle_study_context_key(KeyCode::Char('p'));
    let lines = context_detail_lines(&app, 120).join("\n");
    assert!(
        crate::ui_view_models::study_context::context_header_title(&app)
            .contains("SCANNER CONTEXT PREVIEW")
    );
    let supplied = result["data"]["scannerContextPreview"]["text"]
        .as_str()
        .unwrap();
    assert!(lines
        .split_whitespace()
        .collect::<String>()
        .contains(&supplied.split_whitespace().collect::<String>()));
    assert_eq!(
        app.study_context_picker().unwrap().text_view,
        StudyContextTextView::Scanner
    );
    assert_eq!((app.input(), app.cursor()), ("retained composer", 4));
    let plain = crate::renderer::render_plain_app(&app, 120);
    assert!(plain.contains("SCANNER CONTEXT PREVIEW"));
    assert!(plain.contains("Digest text hash:"));
    assert!(plain.contains("p summary"));
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
    app.handle_study_context_key(KeyCode::Tab);
    assert_eq!(
        app.study_context_picker().unwrap().text_view,
        StudyContextTextView::Document
    );
    app.handle_study_context_key(KeyCode::Char('p'));
    app.handle_study_context_key(KeyCode::Char('p'));
    assert_eq!(
        app.study_context_picker().unwrap().text_view,
        StudyContextTextView::Summary
    );
}

#[test]
fn scanner_context_needs_inspection_and_never_selects_another_revision() {
    let (_root, mut app, _, _) = fixture();
    let selected = app.study_context_picker().unwrap().selected.clone();
    app.handle_study_context_key(KeyCode::Char('p'));
    let lines = context_detail_lines(&app, 40).join("\n");
    assert!(
        crate::ui_view_models::study_context::context_header_title(&app)
            .contains("SCANNER CONTEXT PREVIEW")
    );
    assert!(lines.contains("press Enter"));
    assert_eq!(app.study_context_picker().unwrap().selected, selected);
    app.handle_study_context_key(KeyCode::Up);
    assert_eq!(
        app.study_context_picker().unwrap().text_view,
        StudyContextTextView::Summary
    );
}

#[test]
fn scanner_context_edges_and_pages_preserve_selection_at_every_viewport() {
    let (root, mut app, first, _) = fixture();
    app.handle_study_context_key(KeyCode::Up);
    let result = inspect(&app, root.path(), &first);
    app.cache_tool_snapshot("threat-model:read", &result);
    app.handle_study_context_key(KeyCode::Char('p'));
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        app.handle_study_context_key(KeyCode::End);
        let end = app.study_context_picker().unwrap().detail_scroll;
        app.handle_study_context_key(KeyCode::PageUp);
        assert!(app.study_context_picker().unwrap().detail_scroll <= end);
        app.handle_study_context_key(KeyCode::Home);
        assert_eq!(app.study_context_picker().unwrap().detail_scroll, 0);
        assert_eq!(
            app.study_context_picker().unwrap().selected,
            Some(first.clone())
        );
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(
            text.contains("SCANNER CONTEXT PREVIEW"),
            "{width}x{height}: {text}"
        );
    }
}
