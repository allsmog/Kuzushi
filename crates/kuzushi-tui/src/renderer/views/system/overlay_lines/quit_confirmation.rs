use super::*;

mod layout;
pub(crate) use layout::{quit_disclosure_viewport, render_compact_quit};

pub(super) fn quit_overlay_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let area = overlay_content_area(area);
    quit_viewport_lines(app, area.width as usize, area.height as usize)
}

pub(super) fn quit_page_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    quit_viewport_lines(app, area.width as usize, area.height as usize)
}

fn quit_viewport_lines(app: &ShellApp, width: usize, capacity: usize) -> Vec<Line<'static>> {
    let model = quit_confirm_model(app);
    let actions = quit_actions(&model, width);
    let content = quit_disclosure_lines(&model, width);
    let visible = capacity.saturating_sub(actions.len() + 1);
    let start = app
        .router
        .quit_confirm_scroll()
        .min(content.len().saturating_sub(visible));
    let mut lines: Vec<_> = content.iter().skip(start).take(visible).cloned().collect();
    lines.push(Line::styled(
        fit(&quit_scroll_hint(start, visible, content.len()), width),
        theme::subtle(),
    ));
    lines.extend(actions);
    lines.truncate(capacity);
    lines
}

fn overlay_content_area(area: Rect) -> Rect {
    Rect {
        height: area.height.saturating_sub(4),
        ..area
    }
}

fn quit_actions(model: &QuitConfirmModel, width: usize) -> Vec<Line<'static>> {
    let combined = quit_footer_keybind_line(&model.footer);
    if display_width(combined.trim()) <= width {
        return wrapped_quit_text(&combined, width, theme::accent());
    }
    model
        .footer
        .keybinds
        .iter()
        .flat_map(|(key, label)| {
            wrapped_quit_text(&format!("{key} {label}"), width, theme::accent())
        })
        .collect()
}

fn quit_disclosure_lines(model: &QuitConfirmModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = wrapped_quit_text(&model.warning_title, width, theme::heading());
    lines.extend(wrapped_quit_text(&model.warning_body, width, theme::warn()));
    for section in &model.sections {
        lines.push(Line::styled(fit(&section.title, width), theme::heading()));
        for row in &section.rows {
            lines.extend(wrapped_quit_text(row, width, theme::primary()));
        }
    }
    lines.extend(wrapped_quit_text(
        &model.default_line,
        width,
        theme::subtle(),
    ));
    lines
}

fn wrapped_quit_text(text: &str, width: usize, style: ratatui::style::Style) -> Vec<Line<'static>> {
    wrap_text(text.trim(), width)
        .into_iter()
        .map(|line| Line::styled(line, style))
        .collect()
}

fn quit_scroll_hint(start: usize, visible: usize, total: usize) -> String {
    if visible == 0 {
        return "Resize to read exit details".into();
    }
    if total <= visible {
        return "n/Esc stays in this session".into();
    }
    format!(
        "{}–{} / {total} · ↑/↓ or PgUp/PgDn scroll",
        start + 1,
        (start + visible).min(total)
    )
}

#[cfg(test)]
mod tests;
