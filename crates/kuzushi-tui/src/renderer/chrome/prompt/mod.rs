pub(in crate::renderer) use super::*;
use crate::ui_view_models::prompt_model;

pub(crate) fn render_prompt(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    if let Some(line) = inactive_prompt_line(app) {
        frame.render_widget(Paragraph::new(line), area);
        return;
    }

    let prompt = prompt_model(app);
    let segments = prompt_segments(
        &prompt.prefix,
        &prompt.input,
        prompt.cursor,
        area.width as usize,
        " ",
    );
    let hint = prompt
        .placeholder
        .clone()
        .or_else(|| app.completion_preview())
        .unwrap_or_default();
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
        Span::styled(hint, theme::subtle()),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn inactive_prompt_line(app: &ShellApp) -> Option<Line<'static>> {
    if app.input_mode() == crate::InputMode::Navigate {
        return Some(disabled_prompt_line(
            "NAVIGATION MODE — view keys active · Esc returns to prompt",
        ));
    }
    if matches!(app.shell_view(), crate::ShellView::FilePicker) {
        return Some(disabled_prompt_line(
            "file picker active — type to filter · Enter attach · Esc close",
        ));
    }
    (app.is_picker_view() && !app.picker_prompt_focused())
        .then(|| disabled_prompt_line("command prompt paused — : to type a command"))
}

fn disabled_prompt_line(text: &'static str) -> Line<'static> {
    Line::from(Span::styled(text, theme::disabled()))
}
