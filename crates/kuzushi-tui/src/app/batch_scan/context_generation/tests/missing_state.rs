use super::*;

#[test]
fn missing_guidance_editor_keeps_saved_input_and_allows_return() {
    let (_root, mut app) = fixture();
    let saved = json!({"guidance":"Retain this accepted input"});
    let generation = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .context_generation
        .as_mut()
        .unwrap();
    generation.guidance_editing = true;
    generation.guidance_editor = None;
    generation.context_input = saved.clone();

    for code in [KeyCode::Enter, KeyCode::Left, KeyCode::Char('a')] {
        let update = app
            .handle_regeneration_guidance_key(KeyEvent::new(code, KeyModifiers::NONE))
            .unwrap();
        assert!(update.effects.is_empty());
    }
    assert!(app.capture_regeneration_guidance_paste("replacement"));
    let update = app
        .handle_regeneration_guidance_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL))
        .unwrap();
    assert!(update.effects.is_empty());
    assert_eq!(app.context_generation().unwrap().context_input, saved);
    assert!(app.context_generation().unwrap().guidance_editing);
    assert_missing_editor_views(&mut app);
    app.handle_regeneration_guidance_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(!app.context_generation().unwrap().guidance_editing);
    assert_eq!(app.context_generation().unwrap().context_input, saved);
    assert!(!app.has_running_work());
}

fn assert_missing_editor_views(app: &mut ShellApp) {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let plain =
            crate::ui_view_models::context_generation::generation_lines(app, width as usize)
                .join(" ");
        assert!(plain.contains("Guidance editor unavailable"), "{plain}");
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, app))
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(
            text.contains("Guidance editor unavailable"),
            "{width}x{height}: {text}"
        );
        assert!(text.contains("Esc"), "{text}");
    }
}

#[test]
fn absent_study_does_not_appear_to_load_comparison_results() {
    let app = ShellApp::new(V2Config::default(), None);
    for width in [40, 60, 80, 96, 120, 160] {
        let passes =
            crate::ui_view_models::study_config::context_result_lines(&app, width, 12).join(" ");
        let cases = crate::ui_view_models::matrix_result_lines(&app, width, 12).join(" ");
        for text in [passes, cases] {
            assert!(text.contains("No study selected"), "{text}");
            assert!(!text.contains("Loading"), "{text}");
        }
    }
    assert!(!app.has_running_work());
}
