use super::dag_pane::dag_row_style;
use super::feed_pane::feed_row_style;
use super::*;
use crate::ui_view_models::{
    activity_view_model, ActiveActivityViewModel, ActivityEmptyStateModel, ActivityPlainDagCell,
    ActivityPlainFeedCell, ActivityPlainPaneHeaderCell, ActivityPlainPaneRow, ActivityViewModel,
};
use std::time::Instant;

/// Build the line list for the Activity view. Renders a split-pane layout:
///   left ~46% — DAG status rows (one row per visible task + subsystems aggregate)
///   right ~54% — OUTPUT deck (task detail, findings, and generated artifacts)
///   footer    — single-line focus pane summary
pub(crate) fn activity_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());

    match activity_view_model(app) {
        ActivityViewModel::Active(activity) => active_activity_lines(lines, area, activity),
        ActivityViewModel::Inactive(empty) => inactive_activity_lines(lines, area.width, empty),
    }
}

fn inactive_activity_lines(
    mut lines: Vec<Line<'static>>,
    width: u16,
    empty: ActivityEmptyStateModel,
) -> Vec<Line<'static>> {
    lines.push(divider(empty.title, width));
    lines.extend(empty_state_panel(
        empty.glyph_label,
        empty.explanations,
        empty.ctas,
    ));
    lines
}

fn active_activity_lines(
    mut lines: Vec<Line<'static>>,
    area: Rect,
    activity: ActiveActivityViewModel<'_>,
) -> Vec<Line<'static>> {
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
    lines.extend(footer.hint_rows.iter().map(|row| {
        let pairs = row
            .iter()
            .map(|hint| (hint.plain_key_text, hint.plain_hint_text))
            .collect::<Vec<_>>();
        keybind_hint_line(&pairs)
    }));
    lines
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
