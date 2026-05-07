use super::*;

pub(in crate::renderer) fn render_prompt(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }

    let prompt = match routing_mode(app) {
        RoutingMode::Run => app
            .focused_module
            .as_ref()
            .map(|module| format!("kuzushi/{module}/run> "))
            .unwrap_or_else(|| "kuzushi/run> ".to_string()),
        RoutingMode::Agent => "kuzushi/agent> ".to_string(),
        RoutingMode::Plan => "kuzushi/plan> ".to_string(),
        RoutingMode::Module => app
            .focused_module
            .as_ref()
            .map(|module| format!("kuzushi/{module}> "))
            .unwrap_or_else(|| "kuzushi/module> ".to_string()),
        RoutingMode::Shell => "kuzushi> ".to_string(),
    };
    let segments = prompt_segments(&prompt, &app.input, app.cursor, area.width as usize, " ");
    let line = Line::from(vec![
        // Prompt prefix in c-muted per `design/mockups/_shared.jsx::footer`
        // (`<span className="c-muted">{promptText}</span>`). The Ratatui
        // shell was using c-label (bold blue) which fought with the cursor
        // block for attention; the mockup intentionally lets the cursor be
        // the focal point and keeps the static prefix dim.
        Span::styled(segments.prompt, theme::muted()),
        Span::raw(segments.before_cursor),
        Span::styled(segments.cursor_text, theme::cursor_block()),
        Span::raw(segments.after_cursor),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}
