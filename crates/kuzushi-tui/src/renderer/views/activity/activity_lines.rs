use super::dag_pane::dag_row_style;
use super::feed_pane::feed_row_style;
use super::*;
use crate::ui_view_models::{
    activity_view_model, ActiveActivityViewModel, ActivityEmptyStateModel, ActivityHeartbeatTone,
    ActivityPlainDagCell, ActivityPlainFeedCell, ActivityPlainPaneHeaderCell, ActivityPlainPaneRow,
    ActivityViewModel,
};
use std::time::Instant;

/// Build the line list for the Activity view. Renders a split-pane layout:
///   left ~46% — DAG status rows (one row per visible task + subsystems aggregate)
///   right ~54% — OUTPUT deck (findings and generated artifacts)
///   footer    — single-line focus pane summary
pub(crate) fn activity_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    match activity_view_model(app) {
        ActivityViewModel::Active(activity) => {
            active_activity_lines(activity_context_lines(app, area), area, activity)
        }
        ActivityViewModel::Inactive(empty) => {
            inactive_activity_lines(activity_context_lines(app, area), area.width, empty)
        }
    }
}

fn activity_context_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines
}

fn inactive_activity_lines(
    mut lines: Vec<Line<'static>>,
    width: u16,
    empty: ActivityEmptyStateModel,
) -> Vec<Line<'static>> {
    if width < 70 {
        if lines.last().is_some_and(is_blank_line) {
            lines.pop();
        }
        lines.push(divider(empty.title, width));
        lines.extend(compact_activity_empty_state_lines(&empty, width as usize));
        return lines;
    }
    lines.push(divider(empty.title, width));
    lines.extend(empty_state_panel(
        empty.glyph_label,
        empty.explanations,
        empty.ctas,
    ));
    lines
}

fn compact_activity_empty_state_lines(
    empty: &ActivityEmptyStateModel,
    width: usize,
) -> Vec<Line<'static>> {
    let content_width = width.saturating_sub(2);
    let mut lines = vec![Line::from(vec![
        Span::styled("∅ ", theme::subtle()),
        Span::styled(empty.glyph_label.to_string(), theme::muted()),
    ])];
    if let Some(explanation) = empty.explanations.first() {
        lines.push(muted(&fit(explanation, content_width)));
    }
    lines.extend(
        empty
            .ctas
            .iter()
            .map(|(command, blurb)| compact_activity_cta(command, blurb, content_width)),
    );
    lines
}

fn compact_activity_cta(command: &str, blurb: &str, width: usize) -> Line<'static> {
    let prefix = format!("▸ {command} — ");
    let blurb = fit(blurb, width.saturating_sub(prefix.chars().count()));
    Line::from(vec![
        Span::styled("▸ ", theme::warn()),
        Span::styled(command.to_string(), theme::accent()),
        Span::styled(" — ", theme::subtle()),
        Span::styled(blurb, theme::muted()),
    ])
}

fn is_blank_line(line: &Line<'_>) -> bool {
    line.spans.iter().all(|span| span.content.trim().is_empty())
}

fn active_activity_lines(
    mut lines: Vec<Line<'static>>,
    area: Rect,
    activity: ActiveActivityViewModel<'_>,
) -> Vec<Line<'static>> {
    let header = activity.header();
    lines.push(divider(&header.summary_title, area.width));
    if let Some(phase) = activity.phase_strip() {
        lines.extend(activity_phase_strip_lines(&phase, area.width));
    }
    if let Some(banner) = activity.abort_banner() {
        lines.push(Line::from(vec![Span::styled(banner, theme::warn())]));
    }

    append_activity_pane_lines(&mut lines, area, &activity);

    lines.push(blank());
    append_activity_heartbeat(&mut lines, area.width, &activity);
    append_activity_footer(&mut lines, area.width, &activity);
    lines
}

fn append_activity_heartbeat(
    lines: &mut Vec<Line<'static>>,
    width: u16,
    activity: &ActiveActivityViewModel<'_>,
) {
    let model = activity.heartbeat(Instant::now());
    let style = match model.tone {
        ActivityHeartbeatTone::Live => theme::success(),
        ActivityHeartbeatTone::Stalled => theme::warn(),
        ActivityHeartbeatTone::Complete => theme::muted(),
    };
    lines.push(Line::styled(fit(&model.text, width as usize), style));
}

fn append_activity_pane_lines(
    lines: &mut Vec<Line<'static>>,
    area: Rect,
    activity: &ActiveActivityViewModel<'_>,
) {
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
}

fn append_activity_footer(
    lines: &mut Vec<Line<'static>>,
    width: u16,
    activity: &ActiveActivityViewModel<'_>,
) {
    let footer = activity.footer(width);
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
    theme::muted()
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
