use super::*;

#[test]
fn compact_review_preserves_the_running_tool_cancellation_control() {
    let mut app = workbench_app_with_findings();
    app.set_input_mode(crate::InputMode::Navigate);
    app.set_running_tool_for_test("context:build");
    for width in [40, 60, 80] {
        let mut terminal = Terminal::new(TestBackend::new(width, 3)).unwrap();
        terminal
            .draw(|frame| render_keybind_footer(frame, frame.area(), &app))
            .unwrap();
        let text = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
        assert!(text.contains("Ctrl+C request abort"), "{width}: {text}");
        assert!(!crate::ui_view_models::review_queue_navigation_footer(&app));
    }
}

#[test]
fn review_queue_exposes_filter_detail_groups_and_last_row_across_viewports() {
    let mut app = workbench_app_with_findings();
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ReviewQueue);
    app.set_input_mode(crate::InputMode::Navigate);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let text = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
        for control in [
            "Ctrl+F filter",
            "End last",
            "G groups",
            "Esc prompt",
            "/keys all",
        ] {
            assert!(
                text.contains(control),
                "{width}x{height}: missing {control}\n{text}"
            );
        }
        assert!(
            text.contains("Enter detail") || text.contains("Enter open detail"),
            "{text}"
        );
    }
}
