use super::dag_pane::dag_row_style;
use super::feed_pane::feed_row_style;
use super::*;
use crate::app::ActivitySession;
use crate::ui_view_models::{
    activity_dag_pane_rows, activity_empty_state_model, activity_feed_pane_rows,
    activity_feed_scroll_offset, activity_footer_model, activity_frame_layout,
    activity_header_model, activity_pane_chrome_model, activity_task_scroll_offset,
    ActivityFooterHint, ActivityPaneTitle,
};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Frame, Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use std::time::Instant;

/// Render the Activity view's body region with a true Ratatui horizontal
/// split. Caller is responsible for the surrounding chrome (status footer,
/// transcript, prompt).
///
/// Layout (within `area`):
///
/// ```text
/// ┌─ header (1 row) ──────────────────────────────────────────┐
/// │ ACTIVITY  run r-... · 11/14 done · 2 running              │
/// ├──────────────────────────────────────────────────────────┤
/// │ ┌─ DAG ────────────┬─ FEED ───────────────────────────┐  │
/// │ │ ✓ context:build  │ 15:09:39 [triage:run]            │  │
/// │ │ ▸ patch:finding  │ 15:09:42 [verify:fnd]            │  │
/// │ │ ⤳ subsystems     │ 15:09:48 [patch:fnd]             │  │
/// │ └──────────────────┴──────────────────────────────────┘  │
/// ├─ focus footer (1 row) ───────────────────────────────────┤
/// │ ▸ FOCUS  patch:finding  running 6s · $0.04                │
/// └──────────────────────────────────────────────────────────┘
/// ```
pub(crate) fn render_activity_view(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    let Some(session) = app.activity.as_ref() else {
        let empty = activity_empty_state_model();
        let body = Paragraph::new(Line::from(vec![Span::styled(empty.body, theme::muted())]))
            .alignment(Alignment::Left);
        frame.render_widget(body, area);
        return;
    };

    let layout = activity_frame_layout();
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(layout.header_rows),
            Constraint::Min(0),
            Constraint::Length(layout.footer_rows),
        ])
        .split(area);

    render_header(frame, outer[0], session);

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(layout.dag_percent),
            Constraint::Percentage(layout.feed_percent),
        ])
        .split(outer[1]);

    let pane_chrome = activity_pane_chrome_model(session);
    render_dag_pane_widget(frame, panes[0], session, &pane_chrome.dag);
    render_feed_pane_widget(frame, panes[1], session, &pane_chrome.feed);

    render_focus_footer(frame, outer[2], session);
}

fn render_header(frame: &mut Frame<'_>, area: Rect, session: &ActivitySession) {
    let para = Paragraph::new(activity_header_lines(session));
    frame.render_widget(para, area);
}

fn activity_header_lines(session: &ActivitySession) -> Vec<Line<'static>> {
    let model = activity_header_model(session);
    vec![
        Line::from(vec![Span::styled(model.detailed_title, theme::heading())]),
        Line::from(vec![Span::styled(
            model.focus_label.to_string(),
            theme::accent(),
        )]),
    ]
}

fn render_dag_pane_widget(
    frame: &mut Frame<'_>,
    area: Rect,
    session: &ActivitySession,
    title: &ActivityPaneTitle,
) {
    let now = Instant::now();
    let inner_width = area.width.saturating_sub(2) as usize;
    let lines = dag_pane_lines(session, inner_width, now);
    // `── DAG ──...` divider style mirrors design/mockups/_shared.jsx
    // `sectionHeader` (lines 94-100): leading "── ", labelled segment in
    // c-label, trailing fill in c-subtle.
    let block = Block::default()
        .borders(Borders::RIGHT)
        .border_style(theme::subtle())
        .title(Span::styled(
            title.block_title.clone(),
            pane_title_style(title),
        ));
    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    let scroll = activity_task_scroll_offset(session, lines.len(), inner_area.height as usize);
    let para = Paragraph::new(lines)
        .scroll((scroll as u16, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, inner_area);
}

fn dag_pane_lines(
    session: &ActivitySession,
    inner_width: usize,
    now: Instant,
) -> Vec<Line<'static>> {
    activity_dag_pane_rows(session, inner_width, now)
        .into_iter()
        .map(|row| Line::from(vec![Span::styled(row.text, dag_row_style(row.tone))]))
        .collect()
}

fn render_feed_pane_widget(
    frame: &mut Frame<'_>,
    area: Rect,
    session: &ActivitySession,
    title: &ActivityPaneTitle,
) {
    let inner_width = area.width.saturating_sub(2) as usize;
    let lines = feed_pane_lines(session, inner_width);
    let block = Block::default().borders(Borders::NONE).title(Span::styled(
        title.block_title.clone(),
        pane_title_style(title),
    ));
    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    let scroll = activity_feed_scroll_offset(session, lines.len(), inner_area.height as usize);
    let para = Paragraph::new(lines)
        .scroll((scroll as u16, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, inner_area);
}

fn pane_title_style(title: &ActivityPaneTitle) -> ratatui::style::Style {
    if title.focused {
        return theme::accent();
    }
    theme::label()
}

fn feed_pane_lines(session: &ActivitySession, inner_width: usize) -> Vec<Line<'static>> {
    activity_feed_pane_rows(session, inner_width)
        .into_iter()
        .map(|row| Line::from(vec![Span::styled(row.text, feed_row_style(row.tone))]))
        .collect()
}

fn render_focus_footer(frame: &mut Frame<'_>, area: Rect, session: &ActivitySession) {
    let lines = focus_footer_lines(area.width, session);
    let para = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

fn focus_footer_lines(width: u16, session: &ActivitySession) -> Vec<Line<'static>> {
    let footer = activity_footer_model(session, width);
    vec![
        Line::from(vec![Span::styled(footer.body_line, theme::label())]),
        Line::from(key_hint_spans(footer.hints)),
    ]
}

fn key_hint_spans(hints: &[ActivityFooterHint]) -> Vec<Span<'static>> {
    let mut spans = vec![Span::raw(" ")];
    for (index, hint) in hints.iter().enumerate() {
        append_key_hint(&mut spans, index, hint);
    }
    spans
}

fn append_key_hint(spans: &mut Vec<Span<'static>>, index: usize, hint: &ActivityFooterHint) {
    if index > 0 {
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(hint.full_key_text, theme::accent()));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(hint.full_hint_text, theme::muted()));
}
