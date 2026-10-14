use super::*;

#[test]
fn passive_completion_keeps_the_finding_identity_visible_at_40x12() {
    let mut app = workbench_app_with_findings();
    let target = tempfile::tempdir().unwrap();
    app.set_target(Some(target.path().into()));
    app.set_shell_view(ShellView::Workbench);
    app.set_findings(vec![Finding::new_tool(
        "owned-fixture",
        "owned.marker",
        "main.rs",
        1,
        None,
        Severity::Low,
        "Labeled observation",
    )]);
    app.set_viewport(crate::TerminalViewport::new(40, 12));
    app.set_info_notice("run", "run receipt · completed · 1 run · 0s");
    let mut terminal = Terminal::new(TestBackend::new(40, 12)).unwrap();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let text = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
    assert!(text.contains("F-0001"), "{text}");
    assert!(text.contains("1 finding"), "{text}");
    assert!(text.contains("NOTICE"), "{text}");
    assert!(
        text.contains("logs"),
        "full notice remains reachable: {text}"
    );
    assert_eq!(
        app.advisory().notice.as_ref().unwrap().message,
        "run receipt · completed · 1 run · 0s"
    );
    assert_eq!(app.findings()[0].message, "Labeled observation");
}

#[test]
fn compact_blocking_notices_keep_the_preview_and_escape_hint() {
    let mut app = ShellApp::new(V2Config::default(), None);
    for severity in [crate::NoticeSeverity::Warn, crate::NoticeSeverity::Error] {
        app.clear_notice();
        match severity {
            crate::NoticeSeverity::Warn => app.set_warn_notice("report", "Source evidence could not be authenticated; inspect the recorded decision before exporting."),
            _ => app.set_error_notice("report", "The report destination is unavailable. Choose another path inside this workspace and retry."),
        }
        let area = Rect::new(0, 0, 40, 12);
        let height = notice_banner_height(&app, area);
        assert_eq!(height, NOTICE_BANNER_MAX_LINES as u16);
        let mut terminal = Terminal::new(TestBackend::new(40, height)).unwrap();
        terminal
            .draw(|frame| render_notice_banner(frame, frame.area(), &app))
            .unwrap();
        let text = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
        assert!(text.contains("Esc dismiss"), "{text}");
        assert!(text.contains("Ctrl+G → logs"), "{text}");
    }
}
