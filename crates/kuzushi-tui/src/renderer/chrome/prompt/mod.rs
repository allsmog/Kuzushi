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
    let completion_hint = app.completion_preview_ref();
    let hint = prompt
        .placeholder
        .as_deref()
        .or(completion_hint.as_deref())
        .unwrap_or_default();
    let line = Line::from(vec![
        // Workbench prefixes carry the selected phase accent; other routes
        // retain the quiet shell prefix so the cursor stays the focal point.
        Span::styled(segments.prompt, prompt_prefix_style(prompt.workbench_mode)),
        Span::raw(segments.before_cursor),
        Span::styled(segments.cursor_text, theme::cursor_block()),
        Span::raw(segments.after_cursor),
        Span::styled(hint, theme::subtle()),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn inactive_prompt_line(app: &ShellApp) -> Option<Line<'static>> {
    if let Some(text) = captured_overlay_prompt(app.shell_view()) {
        return Some(disabled_prompt_line(text));
    }
    if app.input_mode() == crate::InputMode::Navigate {
        return Some(navigation_prompt_line(app));
    }
    if matches!(app.shell_view(), crate::ShellView::FilePicker) {
        return Some(disabled_prompt_line(
            "file picker active — type to filter · Enter attach · Esc close",
        ));
    }
    (app.is_picker_view() && !app.picker_prompt_focused())
        .then(|| disabled_prompt_line("command prompt paused — : to type a command"))
}

fn prompt_prefix_style(page: Option<crate::WorkbenchPage>) -> ratatui::style::Style {
    match page {
        Some(crate::WorkbenchPage::Map) => theme::mode_map(),
        Some(crate::WorkbenchPage::Scan) => theme::mode_scan(),
        Some(crate::WorkbenchPage::Review) => theme::mode_review(),
        Some(crate::WorkbenchPage::Prove) => theme::mode_prove(),
        Some(crate::WorkbenchPage::Fix) => theme::mode_fix(),
        None => theme::muted(),
    }
}

fn navigation_prompt_line(app: &ShellApp) -> Line<'static> {
    let Some(page) = crate::ui_view_models::workbench_prompt_mode(app) else {
        return disabled_prompt_line("NAVIGATION MODE — view keys active · Esc returns to prompt");
    };
    Line::from(vec![
        Span::styled(
            crate::ui_view_models::workbench_prompt_token(page),
            prompt_prefix_style(Some(page)),
        ),
        Span::styled(
            crate::ui_view_models::navigation_prompt_text(app),
            theme::disabled(),
        ),
    ])
}

fn captured_overlay_prompt(view: crate::ShellView) -> Option<&'static str> {
    match view {
        crate::ShellView::QuitConfirm => Some("y confirm · n/Esc stay"),
        crate::ShellView::CommandPalette => Some("type to filter · Enter load · Esc close"),
        _ => None,
    }
}

fn disabled_prompt_line(text: &'static str) -> Line<'static> {
    Line::from(Span::styled(text, theme::disabled()))
}
