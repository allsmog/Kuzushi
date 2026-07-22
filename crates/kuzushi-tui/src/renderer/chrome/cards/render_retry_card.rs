use super::*;
use crate::ui_view_models::{retry_card_model, RetryCardModel, RetryCardRow};

pub(crate) fn retry_card_height(app: &ShellApp, area: Rect) -> u16 {
    if area.height < 6 {
        return 0;
    }
    let Some(model) = retry_card_model(app) else {
        return 0;
    };
    // Header + one row per failed task + action line.
    let rows = model.rows.len() as u16;
    (2 + rows).min(area.height.saturating_sub(8)).max(3)
}

pub(crate) fn render_retry_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(model) = retry_card_model(app) else {
        return;
    };
    let width = area.width as usize;
    let mut lines: Vec<Line<'static>> = vec![retry_header_line(&model)];
    for row in &model.rows {
        lines.push(retry_row_line(row, width));
    }
    lines.push(retry_action_line());
    render_lines(frame, area, lines);
}

fn retry_header_line(model: &RetryCardModel) -> Line<'static> {
    Line::from(vec![
        Span::raw(" "),
        Span::styled("⟳ RETRY ", theme::warn()),
        Span::styled(
            format!("{} task(s) failed this engagement", model.failed_count),
            theme::warn(),
        ),
    ])
}

fn retry_row_line(row: &RetryCardRow, width: usize) -> Line<'static> {
    let detail = format!("{} — {}", row.tool, row.error);
    Line::from(vec![
        Span::raw("  ✗ "),
        Span::styled(fit(&detail, width.saturating_sub(4)), theme::muted()),
    ])
}

fn retry_action_line() -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        Span::styled("y", theme::accent()),
        Span::styled(" retry (with fixes)   ", theme::muted()),
        Span::styled("n", theme::accent()),
        Span::styled(" skip", theme::muted()),
    ])
}
