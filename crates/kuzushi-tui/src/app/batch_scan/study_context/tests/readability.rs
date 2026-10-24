use super::*;

fn inspected_reader() -> (tempfile::TempDir, ShellApp, ThreatModelRef) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "fn main() {}\n").unwrap();
    let reference = commit_document(
        root.path(),
        "Reader context",
        &json!({
            "version":"1", "methodology":"stride",
            "systemContext":"Gateway reads invoice records.",
            "dfd":{"nodes":[{"id":"gateway","name":"Gateway","type":"process","trustZone":"internal"}],"flows":[],"trustBoundaries":[]},
            "threats":[], "summary":{}, "openQuestions":["Which callers are trusted?"],
        }),
    );
    commit(root.path(), "Current context");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.open_batch_scan_config(None);
    app.hydrate_all_view_data_for_test();
    app.open_study_context_picker();
    app.handle_study_context_key(KeyCode::Up);
    let mut response = inspect(&app, root.path(), &reference);
    response["data"]["sourceState"] = json!({"status":"matches","message":"Source identity matched at inspection. Claims remain unverified."});
    app.cache_tool_snapshot("threat-model:read", &response);
    assert!(app.study_context_picker().unwrap().preview.is_some());
    (root, app, reference)
}

fn frame_text(app: &ShellApp, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    format!("{:?}", terminal.backend().buffer())
}

#[test]
fn inspected_context_first_frame_shows_architecture_at_every_size() {
    let (_root, mut app, reference) = inspected_reader();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        app.handle_study_context_key(KeyCode::Home);
        let frame = frame_text(&app, width, height);
        assert!(
            frame.contains("Gateway reads invoice records."),
            "{width}x{height}: {frame}"
        );
        assert!(frame.contains("Reader context"), "{frame}");
        assert!(frame.contains("Source matched at inspection."), "{frame}");
        assert_eq!(
            app.study_context_picker().unwrap().selected.as_ref(),
            Some(&reference)
        );
    }
}

#[test]
fn narrow_context_reader_pages_reach_source_metadata_without_changing_selection() {
    let (root, mut app, reference) = inspected_reader();
    let active = load_active_threat_model(root.path())
        .unwrap()
        .unwrap()
        .model_ref;
    app.set_input("retained study draft");
    app.set_cursor(7);
    app.reduce_resize(40, 12);
    let mut seen = String::new();
    loop {
        seen.push_str(&frame_text(&app, 40, 12));
        let offset = app.study_context_picker().unwrap().detail_scroll;
        app.handle_study_context_key(KeyCode::PageDown);
        if app.study_context_picker().unwrap().detail_scroll == offset {
            break;
        }
    }
    for text in [
        "Which callers are trusted?",
        "CONTEXT DETAILS AND LIMITS",
        "Recorded source revision:",
        "Context digest:",
        "No model",
    ] {
        assert!(seen.contains(text), "missing {text}: {seen}");
    }
    app.handle_study_context_key(KeyCode::Home);
    assert!(frame_text(&app, 40, 12).contains("Gateway reads invoice records."));
    assert_eq!(
        app.study_context_picker().unwrap().selected.as_ref(),
        Some(&reference)
    );
    app.handle_study_context_key(KeyCode::Esc);
    assert_eq!((app.input(), app.cursor()), ("retained study draft", 7));
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        active
    );
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn inspected_reader_keeps_drift_and_unknown_source_warnings_before_architecture() {
    let (root, mut app, reference) = inspected_reader();
    for (status, label) in [
        (json!("drifted"), "Earlier source; read only. Replan."),
        (Value::Null, "Source unchecked; inspect details."),
    ] {
        let mut response = inspect(&app, root.path(), &reference);
        response["data"]["sourceState"] =
            json!({"status":status,"message":"Full source state details stay readable."});
        app.cache_tool_snapshot("threat-model:read", &response);
        app.reduce_resize(40, 12);
        let frame = frame_text(&app, 40, 12);
        assert!(frame.contains(label), "{frame}");
        assert!(frame.contains("Gateway reads invoice records."), "{frame}");
        let plain = crate::renderer::render_plain_app(&app, 80);
        assert!(plain.contains("Full source state details stay readable."));
        assert!(!frame.contains("Source matched at inspection."));
    }
}
