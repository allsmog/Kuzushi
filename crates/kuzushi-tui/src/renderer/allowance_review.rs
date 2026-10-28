use super::*;
use crate::ui_view_models::{allowance_review_model, allowance_review_width, AllowanceReviewModel};
use ratatui::widgets::{Block, Borders, Clear};

pub(super) fn render_allowance_review(frame: &mut Frame<'_>, app: &ShellApp) -> bool {
    if app.shell_view() == ShellView::QuitConfirm {
        return false;
    }
    let full = frame.area();
    let Some(model) = allowance_review_model(app, full.width, full.height) else {
        return false;
    };
    let width = allowance_review_width(full.width);
    let area = Rect::new(
        full.x + (full.width - width) / 2,
        full.y,
        width,
        full.height,
    );
    frame.render_widget(Clear, full);
    frame.render_widget(review_block(&model), area);
    render_pinned_terms(frame, area, &model);
    let body = Rect::new(
        area.x + 2,
        area.y + 2 + model.pinned.len() as u16,
        width.saturating_sub(4),
        model.page_rows as u16,
    );
    let lines = model
        .lines
        .iter()
        .skip(model.offset)
        .take(model.page_rows)
        .map(|line| review_line(line))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), body);
    render_review_controls(frame, area, &model);
    true
}

fn render_pinned_terms(frame: &mut Frame<'_>, area: Rect, model: &AllowanceReviewModel) {
    let lines = model
        .pinned
        .iter()
        .map(|line| Line::styled(line.clone(), theme::accent()))
        .collect::<Vec<_>>();
    let summary = Rect::new(
        area.x + 2,
        area.y + 1,
        area.width.saturating_sub(4),
        model.pinned.len() as u16,
    );
    frame.render_widget(Paragraph::new(lines), summary);
}

fn review_line(line: &str) -> Line<'static> {
    readable_line(line)
}

fn review_block(model: &AllowanceReviewModel) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(theme::subtle())
        .title(Span::styled(format!(" {} ", model.title), theme::heading()))
        .title_bottom(Line::from(format!(" {} ", model.position())).right_aligned())
}

fn render_review_controls(frame: &mut Frame<'_>, area: Rect, model: &AllowanceReviewModel) {
    let action = if model.allows_approval() {
        "y approve · n cancel · $ unknown"
    } else {
        "Read more to approve · $ unknown"
    };
    let lines = vec![
        Line::styled("PgUp/PgDn read · Esc cancel", theme::muted()),
        Line::styled(action, theme::accent()),
    ];
    let footer = Rect::new(
        area.x + 2,
        area.bottom().saturating_sub(3),
        area.width.saturating_sub(4),
        2,
    );
    frame.render_widget(Paragraph::new(lines), footer);
}

pub(crate) fn allowance_review_plain_lines(app: &ShellApp, width: usize) -> Option<Vec<String>> {
    if app.shell_view() == ShellView::QuitConfirm {
        return None;
    }
    let model = allowance_review_model(app, width.min(u16::MAX as usize) as u16, u16::MAX)?;
    let mut lines = vec![model.title.to_owned(), String::new()];
    lines.extend(model.pinned);
    lines.extend(model.lines);
    lines.push("Review terms · y approve · Esc cancel".into());
    Some(lines)
}
