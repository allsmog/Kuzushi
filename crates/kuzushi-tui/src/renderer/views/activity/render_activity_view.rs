use super::dag_pane::dag_row_style;
use super::feed_pane::feed_row_style;
use super::*;
use crate::ui_view_models::{
    activity_view_model, phase_cockpit_model, ActiveActivityViewModel, ActivityFooterHint,
    ActivityPaneTitle, ActivityViewModel, PhaseCockpitModel,
};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Frame, Line, Span};
use ratatui::style::Modifier;
use ratatui::widgets::{Paragraph, Wrap};
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
/// │ │ · patch:finding  │ 15:09:42 [verify:fnd]            │  │
/// │ │ ⤳ subsystems     │ 15:09:48 [patch:fnd]             │  │
/// │ └──────────────────┴──────────────────────────────────┘  │
/// ├─ focus footer (1 row) ───────────────────────────────────┤
/// │ ● FOCUS  patch:finding  running 6s · $0.04                │
/// └──────────────────────────────────────────────────────────┘
/// ```
pub(crate) fn render_activity_view(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    paint_cinematic_background(frame.buffer_mut(), area);
    paint_cinematic_scanlines(frame.buffer_mut(), area);
    match activity_view_model(app) {
        ActivityViewModel::Active(activity) => {
            if let Some(phase) = phase_cockpit_model(app) {
                render_phase_activity_view(frame, area, app, &activity, &phase);
            } else {
                render_active_activity_view(frame, area, &activity);
            }
        }
        ActivityViewModel::Inactive(empty) => {
            let mut lines = vec![divider(empty.title, area.width)];
            lines.extend(empty_state_panel(
                empty.glyph_label,
                empty.explanations,
                empty.ctas,
            ));
            let body = Paragraph::new(lines).alignment(Alignment::Left);
            frame.render_widget(body, area);
        }
    }
}

fn render_phase_activity_view(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    activity: &ActiveActivityViewModel<'_>,
    phase: &PhaseCockpitModel,
) {
    let phase_header = activity_phase_header_lines(&phase.header, area);
    let activity_header = activity_header_lines(activity);
    let footer = activity.footer(area.width);
    let footer_rows = (1 + footer.hint_rows.len().max(1)) as u16;
    let fixed_rows = phase_header
        .len()
        .saturating_add(activity_header.len())
        .saturating_add(footer_rows as usize) as u16;
    let (phase_body_rows, activity_pane_rows) =
        phase_activity_body_rows(area.height.saturating_sub(fixed_rows));
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(phase_header.len() as u16),
            Constraint::Length(phase_body_rows),
            Constraint::Length(activity_header.len() as u16),
            Constraint::Length(activity_pane_rows),
            Constraint::Length(footer_rows),
        ])
        .split(area);
    render_header(frame, outer[0], phase_header);
    super::super::workbench::render_phase_cockpit_body(
        frame,
        outer[1],
        app,
        phase,
        super::super::workbench::PhaseRenderState::activity(),
    );
    render_header(frame, outer[2], activity_header);
    render_activity_panes(frame, outer[3], activity);
    render_focus_footer(frame, outer[4], activity);
}

fn phase_activity_body_rows(available: u16) -> (u16, u16) {
    let activity = match available {
        18.. => (available / 3).clamp(6, 10),
        10..=17 => 4,
        6..=9 => 3,
        _ => available / 2,
    };
    (available.saturating_sub(activity), activity)
}

fn render_active_activity_view(
    frame: &mut Frame<'_>,
    area: Rect,
    activity: &ActiveActivityViewModel<'_>,
) {
    let header_lines = activity_header_lines(activity);
    // Footer height tracks the wrapped hint rows so narrow terminals get a
    // second hint line instead of keys clipped off the right edge.
    let footer = activity.footer(area.width);
    let footer_rows = (1 + footer.hint_rows.len().max(1)) as u16;
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header_lines.len() as u16),
            Constraint::Min(0),
            Constraint::Length(footer_rows),
        ])
        .split(area);

    render_header(frame, outer[0], header_lines);

    render_activity_panes(frame, outer[1], activity);

    render_focus_footer(frame, outer[2], activity);
}

fn render_activity_panes(
    frame: &mut Frame<'_>,
    area: Rect,
    activity: &ActiveActivityViewModel<'_>,
) {
    let layout = activity.frame_layout();
    let pane_chrome = activity.pane_chrome();
    if activity.collapse_dag_pane() {
        // No DAG tasks (single-tool run): the TASKS pane would only say
        // "(no DAG tasks yet)" forever — give the OUTPUT pane full width.
        render_feed_pane_widget(frame, area, activity, &pane_chrome.feed);
    } else {
        let panes = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(activity_pane_constraints(area.width, layout))
            .split(area);
        render_dag_pane_widget(frame, panes[0], activity, &pane_chrome.dag);
        render_feed_pane_widget(frame, panes[1], activity, &pane_chrome.feed);
    }
}

fn render_header(frame: &mut Frame<'_>, area: Rect, lines: Vec<Line<'static>>) {
    let para = Paragraph::new(lines);
    frame.render_widget(para, area);
}

fn activity_header_lines(activity: &ActiveActivityViewModel<'_>) -> Vec<Line<'static>> {
    let model = activity.header();
    let mut lines = vec![
        Line::from(vec![Span::styled(model.detailed_title, theme::heading())]),
        Line::from(vec![Span::styled(
            activity.context_line().to_string(),
            theme::muted(),
        )]),
    ];
    if let Some(banner) = activity.abort_banner() {
        lines.push(Line::from(vec![Span::styled(banner, theme::warn())]));
    }
    lines
}

fn render_dag_pane_widget(
    frame: &mut Frame<'_>,
    area: Rect,
    activity: &ActiveActivityViewModel<'_>,
    title: &ActivityPaneTitle,
) {
    let now = Instant::now();
    let inner_width = area.width.saturating_sub(2) as usize;
    let lines = dag_pane_lines(activity, inner_width, now);
    // `── DAG ──...` divider style mirrors design/mockups/_shared.jsx
    // `sectionHeader` (lines 94-100): leading "── ", labelled segment in
    // c-label, trailing fill in c-subtle.
    let block = cockpit_pane_block(
        Line::from(Span::styled(
            title.block_title.clone(),
            pane_title_style(title),
        )),
        title.focused,
    );
    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    let scroll = activity.task_scroll_offset(lines.len(), inner_area.height as usize);
    let para = Paragraph::new(lines)
        .scroll((scroll as u16, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, inner_area);
}

fn dag_pane_lines(
    activity: &ActiveActivityViewModel<'_>,
    inner_width: usize,
    now: Instant,
) -> Vec<Line<'static>> {
    activity
        .dag_pane_rows(inner_width, now)
        .into_iter()
        .map(|row| Line::from(vec![Span::styled(row.text, dag_row_style(row.tone))]))
        .collect()
}

fn render_feed_pane_widget(
    frame: &mut Frame<'_>,
    area: Rect,
    activity: &ActiveActivityViewModel<'_>,
    title: &ActivityPaneTitle,
) {
    let inner_width = area.width.saturating_sub(2) as usize;
    let lines = feed_pane_lines(activity, inner_width);
    let block = cockpit_pane_block(
        Line::from(Span::styled(
            title.block_title.clone(),
            pane_title_style(title),
        )),
        title.focused,
    );
    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    let scroll = activity.feed_scroll_offset(lines.len(), inner_area.height as usize);
    let para = Paragraph::new(lines)
        .scroll((scroll as u16, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, inner_area);
}

fn pane_title_style(title: &ActivityPaneTitle) -> ratatui::style::Style {
    if title.focused {
        return theme::accent().add_modifier(Modifier::BOLD);
    }
    theme::muted()
}

fn activity_pane_constraints(
    width: u16,
    layout: crate::ui_view_models::ActivityFrameLayout,
) -> [Constraint; 2] {
    if width >= layout.compact_breakpoint {
        [
            Constraint::Length(layout.wide_dag_width),
            Constraint::Min(0),
        ]
    } else {
        [
            Constraint::Percentage(layout.compact_dag_percent),
            Constraint::Min(0),
        ]
    }
}

fn feed_pane_lines(
    activity: &ActiveActivityViewModel<'_>,
    inner_width: usize,
) -> Vec<Line<'static>> {
    activity
        .feed_pane_rows(inner_width)
        .into_iter()
        .map(|row| Line::from(vec![Span::styled(row.text, feed_row_style(row.tone))]))
        .collect()
}

fn render_focus_footer(frame: &mut Frame<'_>, area: Rect, activity: &ActiveActivityViewModel<'_>) {
    let lines = focus_footer_lines(area.width, activity);
    let para = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

fn focus_footer_lines(width: u16, activity: &ActiveActivityViewModel<'_>) -> Vec<Line<'static>> {
    let footer = activity.footer(width);
    let mut lines = vec![Line::from(vec![Span::styled(
        footer.body_line,
        theme::label(),
    )])];
    for row in &footer.hint_rows {
        lines.push(Line::from(key_hint_spans(row)));
    }
    lines
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
