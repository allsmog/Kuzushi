use super::dag_pane::dag_row_style;
use super::feed_pane::feed_row_style;
use super::*;
use crate::ui_view_models::{
    activity_view_model, ActivityPlainDagCell, ActivityPlainFeedCell, ActivityPlainPaneHeaderCell,
    ActivityPlainPaneRow, ActivityViewModel,
};
use std::time::Instant;

/// Build the line list for the Activity view. Renders a split-pane layout:
///   left ~46% — DAG status rows (one row per visible task + subsystems aggregate)
///   right ~54% — chronological reasoning feed `[module:verb] label`
///   footer    — single-line focus pane summary
pub(crate) fn activity_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());

    let activity = match activity_view_model(app) {
        ActivityViewModel::Active(activity) => activity,
        ActivityViewModel::Inactive(empty) => {
            push_inactive_activity_lines(&mut lines, area.width, empty.title, empty.body);
            return lines;
        }
    };

    let header = activity.header();
    lines.push(divider(&header.summary_title, area.width));

    let widths = activity.plain_pane_widths(area.width);
    let pane_header = activity.plain_pane_header(widths);
    lines.push(Line::from(vec![
        pane_header_cell_span(&pane_header.dag),
        Span::styled(pane_header.separator.to_string(), theme::subtle()),
        pane_header_cell_span(&pane_header.feed),
    ]));
    lines.extend(
        activity
            .plain_pane_rows(widths, Instant::now())
            .into_iter()
            .map(activity_pane_line),
    );

    lines.push(blank());
    let footer = activity.footer(area.width);
    lines.push(Line::from(vec![Span::styled(
        footer.body_line,
        theme::label(),
    )]));
    lines.push(keybind_hint_line(&footer.plain_hints));
    lines
}

fn push_inactive_activity_lines(
    lines: &mut Vec<Line<'static>>,
    width: u16,
    title: &'static str,
    body: &'static str,
) {
    lines.push(divider(title, width));
    lines.push(muted(body));
}

fn activity_pane_line(row: ActivityPlainPaneRow) -> Line<'static> {
    Line::from(vec![
        dag_cell_span(&row.dag),
        Span::styled(row.separator.to_string(), theme::subtle()),
        feed_cell_span(&row.feed),
    ])
}

fn pane_title_style(cell: &ActivityPlainPaneHeaderCell) -> ratatui::style::Style {
    if cell.focused {
        return theme::accent();
    }
    theme::label()
}

fn pane_header_cell_span(cell: &ActivityPlainPaneHeaderCell) -> Span<'static> {
    Span::styled(cell.text.clone(), pane_title_style(cell))
}

fn dag_cell_span(cell: &ActivityPlainDagCell) -> Span<'static> {
    Span::styled(cell.text.clone(), dag_cell_style(cell))
}

fn feed_cell_span(cell: &ActivityPlainFeedCell) -> Span<'static> {
    Span::styled(cell.text.clone(), feed_cell_style(cell))
}

fn dag_cell_style(cell: &ActivityPlainDagCell) -> ratatui::style::Style {
    cell.tone.map(dag_row_style).unwrap_or_else(theme::primary)
}

fn feed_cell_style(cell: &ActivityPlainFeedCell) -> ratatui::style::Style {
    cell.tone.map(feed_row_style).unwrap_or_else(theme::primary)
}
