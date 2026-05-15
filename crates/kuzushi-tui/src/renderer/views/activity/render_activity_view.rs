use super::dag_pane::{dag_row_text, dag_state_style, dag_subsystems_row_text};
use super::feed_pane::{feed_event_style, feed_event_text};
use super::*;
use crate::app::ActivitySession;
use crate::ui_view_models::{
    activity_feed_pause_model, activity_feed_placeholder_model, activity_feed_scroll_offset,
    activity_footer_model, activity_header_model, activity_pane_chrome_model,
    activity_task_scroll_offset, ActivityFooterHint, ActivityPaneTitle,
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
/// │ ┌─ DAG (46%) ──────┬─ FEED (54%) ─────────────────────┐  │
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
        let body = Paragraph::new(Line::from(vec![Span::styled(
            "(no run active; start one with `scan` or `run <tool>` and the feed will appear here)"
                .to_string(),
            theme::muted(),
        )]))
        .alignment(Alignment::Left);
        frame.render_widget(body, area);
        return;
    };

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(0),
            Constraint::Length(2),
        ])
        .split(area);

    render_header(frame, outer[0], session);

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
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
            pane_title_text(title),
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
    let mut lines: Vec<Line<'static>> = Vec::new();
    for row in session.tasks.values() {
        let text = dag_row_text(row, inner_width, now);
        lines.push(Line::from(vec![Span::styled(
            text,
            dag_state_style(row.state),
        )]));
    }
    push_subsystems_line(&mut lines, session, inner_width);
    ensure_dag_placeholder(&mut lines);
    lines
}

fn push_subsystems_line(
    lines: &mut Vec<Line<'static>>,
    session: &ActivitySession,
    inner_width: usize,
) {
    if let Some(text) = dag_subsystems_row_text(session, inner_width) {
        lines.push(Line::from(vec![Span::styled(text, theme::muted())]));
    }
}

fn ensure_dag_placeholder(lines: &mut Vec<Line<'static>>) {
    if lines.is_empty() {
        lines.push(Line::from(vec![Span::styled(
            " (no DAG tasks yet)".to_string(),
            theme::muted(),
        )]));
    }
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
        pane_title_text(title),
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

fn pane_title_text(title: &ActivityPaneTitle) -> String {
    format!("── {} ──", title.label)
}

fn pane_title_style(title: &ActivityPaneTitle) -> ratatui::style::Style {
    if title.focused {
        return theme::accent();
    }
    theme::label()
}

fn feed_pane_lines(session: &ActivitySession, inner_width: usize) -> Vec<Line<'static>> {
    let mut lines = feed_pause_line(session).into_iter().collect::<Vec<_>>();
    lines.extend(visible_feed_event_lines(session, inner_width));
    ensure_feed_placeholder(&mut lines, session);
    lines
}

fn feed_pause_line(session: &ActivitySession) -> Option<Line<'static>> {
    activity_feed_pause_model(session).map(|model| {
        Line::from(vec![Span::styled(
            format!(" {}", model.text),
            theme::warn(),
        )])
    })
}

fn visible_feed_event_lines(session: &ActivitySession, inner_width: usize) -> Vec<Line<'static>> {
    session
        .events
        .iter()
        .filter_map(|event| {
            feed_event_text(event, session.verbose_subsystems, inner_width)
                .map(|text| Line::from(vec![Span::styled(text, feed_event_style(event))]))
        })
        .collect()
}

fn ensure_feed_placeholder(lines: &mut Vec<Line<'static>>, session: &ActivitySession) {
    if let (true, Some(model)) = (lines.is_empty(), activity_feed_placeholder_model(session)) {
        lines.push(Line::from(vec![Span::styled(model.text, theme::muted())]));
    }
}

fn render_focus_footer(frame: &mut Frame<'_>, area: Rect, session: &ActivitySession) {
    let lines = focus_footer_lines(area.width, session);
    let para = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

fn focus_footer_lines(width: u16, session: &ActivitySession) -> Vec<Line<'static>> {
    let footer = activity_footer_model(session, width);
    vec![
        Line::from(vec![Span::styled(footer.body, theme::label())]),
        Line::from(key_hint_spans(footer.hints)),
    ]
}

fn key_hint_spans(hints: &[ActivityFooterHint]) -> Vec<Span<'static>> {
    let mut spans = vec![Span::raw(" ")];
    for (index, hint) in hints.iter().enumerate() {
        append_key_hint(&mut spans, index, hint.key, hint.hint);
    }
    spans
}

fn append_key_hint(spans: &mut Vec<Span<'static>>, index: usize, key: &str, hint: &str) {
    if index > 0 {
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(format!("[{key}"), theme::accent()));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(format!("{hint}]"), theme::muted()));
}
