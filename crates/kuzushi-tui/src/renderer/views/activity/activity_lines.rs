use super::dag_pane::dag_row_style;
use super::feed_pane::feed_row_style;
use super::*;
use crate::ui_view_models::{
    activity_dag_pane_rows, activity_empty_state_model, activity_feed_pane_rows,
    activity_footer_model, activity_header_model, activity_pane_chrome_model,
    activity_plain_pane_widths, ActivityFooterHint, ActivityPaneTitle,
};
use std::time::Instant;

/// Build the line list for the Activity view. Renders a split-pane layout:
///   left ~46% — DAG status rows (one row per visible task + subsystems aggregate)
///   right ~54% — chronological reasoning feed `[module:verb] label`
///   footer    — single-line focus pane summary
pub(crate) fn activity_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());

    let Some(session) = app.activity.as_ref() else {
        push_inactive_activity_lines(&mut lines, area.width);
        return lines;
    };

    let header = activity_header_model(session);
    lines.push(divider(&header.summary_title, area.width));

    let widths = activity_plain_pane_widths(area.width);
    let pane_chrome = activity_pane_chrome_model(session);
    lines.push(pane_header_line(
        &pane_chrome.dag,
        &pane_chrome.feed,
        widths.dag,
        widths.feed,
    ));
    lines.extend(activity_pane_lines(session, widths.dag, widths.feed));

    lines.push(blank());
    let footer = activity_footer_model(session, area.width);
    lines.push(focus_footer_line(&footer.body, area.width));
    lines.push(activity_keybind_hint_line(footer.hints));
    lines
}

type ActivityPaneRow = (String, ratatui::style::Style);

fn push_inactive_activity_lines(lines: &mut Vec<Line<'static>>, width: u16) {
    let empty = activity_empty_state_model();
    lines.push(divider(empty.title, width));
    lines.push(muted(empty.body));
}

fn activity_pane_lines(
    session: &crate::app::ActivitySession,
    left_w: usize,
    right_w: usize,
) -> Vec<Line<'static>> {
    let left_rows = dag_pane_rows(session, left_w);
    let right_rows = feed_pane_rows(session, right_w);
    let max_rows = left_rows.len().max(right_rows.len());
    (0..max_rows)
        .map(|index| combined_activity_pane_line(&left_rows, &right_rows, index, left_w, right_w))
        .collect()
}

fn dag_pane_rows(session: &crate::app::ActivitySession, left_w: usize) -> Vec<ActivityPaneRow> {
    activity_dag_pane_rows(session, left_w, Instant::now())
        .into_iter()
        .map(|row| (row.text, dag_row_style(row.tone)))
        .collect()
}

fn feed_pane_rows(session: &crate::app::ActivitySession, right_w: usize) -> Vec<ActivityPaneRow> {
    activity_feed_pane_rows(session, right_w)
        .into_iter()
        .map(|row| (row.text, feed_row_style(row.tone)))
        .collect()
}

fn combined_activity_pane_line(
    left_rows: &[ActivityPaneRow],
    right_rows: &[ActivityPaneRow],
    index: usize,
    left_w: usize,
    right_w: usize,
) -> Line<'static> {
    let (left_text, left_style) = left_rows
        .get(index)
        .cloned()
        .unwrap_or((" ".repeat(left_w), theme::primary()));
    let (right_text, right_style) = right_rows
        .get(index)
        .cloned()
        .unwrap_or((String::new(), theme::primary()));
    combined_pane_line(
        left_text,
        left_style,
        right_text,
        right_style,
        left_w,
        right_w,
    )
}

fn pane_header_line(
    left: &ActivityPaneTitle,
    right: &ActivityPaneTitle,
    left_w: usize,
    right_w: usize,
) -> Line<'static> {
    Line::from(vec![
        Span::styled(pad_to(&left.plain_header, left_w), pane_title_style(left)),
        Span::styled("│".to_string(), theme::subtle()),
        Span::styled(
            pad_to(&right.plain_header, right_w),
            pane_title_style(right),
        ),
    ])
}

fn pane_title_style(title: &ActivityPaneTitle) -> ratatui::style::Style {
    if title.focused {
        return theme::accent();
    }
    theme::label()
}

fn combined_pane_line(
    left_text: String,
    left_style: ratatui::style::Style,
    right_text: String,
    right_style: ratatui::style::Style,
    left_w: usize,
    right_w: usize,
) -> Line<'static> {
    Line::from(vec![
        Span::styled(pad_to(&left_text, left_w), left_style),
        Span::styled("│".to_string(), theme::subtle()),
        Span::styled(pad_to(&right_text, right_w), right_style),
    ])
}

fn focus_footer_line(body: &str, width: u16) -> Line<'static> {
    Line::from(vec![Span::styled(
        fit(body, width as usize),
        theme::label(),
    )])
}

fn activity_keybind_hint_line(hints: &[ActivityFooterHint]) -> Line<'static> {
    let pairs = hints
        .iter()
        .map(|hint| (hint.key, hint.hint))
        .collect::<Vec<_>>();
    keybind_hint_line(&pairs)
}

fn pad_to(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.chars().take(width).collect()
    } else {
        let mut out = s.to_string();
        out.push_str(&" ".repeat(width - len));
        out
    }
}
