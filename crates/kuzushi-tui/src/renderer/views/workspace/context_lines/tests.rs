use super::*;

#[test]
fn context_page_size_uses_the_actual_body_at_every_supported_viewport() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_shell_view(ShellView::Context);
    for (width, height) in [(120, 36), (160, 48), (96, 89), (80, 24), (60, 20), (40, 12)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let body = crate::renderer::primary_body_area(&app, Rect::new(0, 0, width, height));
        assert_eq!(
            context_page_rows(&app),
            Some(usize::from(body.height).max(1))
        );
    }
    app.set_shell_view(ShellView::Workspace);
    assert_eq!(context_page_rows(&app), None);
}

#[test]
fn narrow_context_retains_complete_paths_and_recovery_text() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let path = "/owned/context/repository/with/a/long/component/path/and/complete/membership";
    let status = "Source content changed. Inspect the historical snapshot or run context build.";
    let view = app.domain_mut().context_view_mut();
    view.exists = true;
    view.target = Some(path.into());
    view.status = status.into();
    view.languages = vec!["Rust".into(), "Python".into(), "TypeScript".into()];
    let lines = context_lines(&app, Rect::new(0, 0, 40, 12));
    assert!(
        lines.iter().all(|line| line.width() <= 40),
        "{:?}",
        lines
            .iter()
            .filter(|line| line.width() > 40)
            .collect::<Vec<_>>()
    );
    let text = lines
        .iter()
        .flat_map(|line| line.spans.iter().map(|span| span.content.as_ref()))
        .collect::<String>();
    let compact = text
        .chars()
        .filter(|value| !value.is_whitespace())
        .collect::<String>();
    assert!(compact.contains(path), "{text}");
    assert!(compact.contains(&status.replace(' ', "")), "{text}");
    assert!(text.contains("TypeScript"));
    for command in [
        "context build",
        "context status",
        "context regen repo",
        "context regen app-model",
    ] {
        assert!(text.contains(command), "{text}");
    }
}
