pub(in crate::renderer) use super::*;
use crate::ui_view_models::{prompt_brand, routing_mode, RoutingMode};

pub(crate) fn render_prompt(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }

    let prompt = prompt_text(
        prompt_brand(),
        routing_mode(app),
        app.focused_module.as_deref(),
    );
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

pub(in crate::renderer) fn prompt_text(
    brand: &str,
    mode: RoutingMode,
    focused_module: Option<&str>,
) -> String {
    match mode {
        RoutingMode::Run => focused_module
            .map(|module| format!("{brand}/{module}/run> "))
            .unwrap_or_else(|| format!("{brand}/run> ")),
        RoutingMode::Agent => format!("{brand}/agent> "),
        RoutingMode::Plan => format!("{brand}/plan> "),
        RoutingMode::Module => focused_module
            .map(|module| format!("{brand}/{module}> "))
            .unwrap_or_else(|| format!("{brand}/module> ")),
        RoutingMode::Shell => format!("{brand}> "),
    }
}
