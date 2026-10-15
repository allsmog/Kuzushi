use super::*;

#[test]
fn setup_launch_failure_is_visible_and_fully_readable_at_every_supported_size() {
    let (_root, mut app) = import_setup();
    app.router.setup_mut().set_cursor(7);
    let cause = format!(
        "context:build launch blocked: could not initialize run artifacts: {}Effective Git ignore policy hides trackable workspace path `.kuzushi/scope.toml`; update parent and .kuzushi ignore rules",
        "owned directory boundary / ".repeat(12)
    );
    app.router.setup_mut().record_launch_failure(cause);
    let detail = setup_readiness_model(&app).rows[7].detail.clone();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        app.router.setup_mut().finish_editor();
        assert!(draw(&app).contains("RETRY"), "{width}x{height}");
        key(&mut app, KeyCode::Tab);
        assert_eq!(app.router.setup().editor(), Some(SetupEditor::Details));
        app.router.setup_mut().set_detail_scroll(0);
        let mut seen = String::new();
        for _ in 0..60 {
            seen.push_str(&draw(&app));
            key(&mut app, KeyCode::PageDown);
        }
        let body = crate::renderer::workbench_primary_area(&app, Rect::new(0, 0, width, height));
        for fragment in wrap_text(&detail, body.width as usize) {
            assert!(seen.contains(&fragment), "{width}x{height}: {fragment:?}");
        }
        let plain = crate::renderer::render_plain_app(&app, width as usize);
        assert!(plain.contains("LAST START FAILED"));
        key(&mut app, KeyCode::Tab);
        assert_eq!(app.router.setup().cursor(), 7);
        assert!(!app.has_running_work());
    }
}
