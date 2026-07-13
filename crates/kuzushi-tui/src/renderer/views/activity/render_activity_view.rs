use super::dag_pane::dag_row_style;
use super::feed_pane::feed_row_style;
use super::*;
use crate::ui_view_models::{
    activity_view_model, ActiveActivityViewModel, ActivityFooterHint, ActivityHeartbeatTone,
    ActivityPaneTitle, ActivityPhaseStripModel, ActivityViewModel,
};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Frame, Line, Span};
use ratatui::style::Modifier;
use ratatui::widgets::{Paragraph, Wrap};
use std::time::Instant;

const SINGLE_PANE_BREAKPOINT: u16 = 70;
const STACKED_PANE_MIN_HEIGHT: u16 = 40;

/// Render the Activity view as a run-owned surface with compact phase context,
/// adaptive output/task panes, and a fixed progress heartbeat.
///
/// Layout (within `area`):
///
/// ```text
/// ┌─ header (1 row) ──────────────────────────────────────────┐
/// │ ACTIVITY  run r-... · 11/14 done · 2 running              │
/// ├──────────────────────────────────────────────────────────┤
/// │ ┌─ OUTPUT ─────────┬─ TASKS ──────────────────────────┐  │
/// │ │ build trace      │ ✓ context:build                 │  │
/// │ │ ▸ map surface    │ 15:09:39 [context:build]        │  │
/// │ │ · write snapshot │ 15:09:42 stage 4/5             │  │
/// │ └──────────────────┴──────────────────────────────────┘  │
/// ├─ heartbeat (1 row) ──────────────────────────────────────┤
/// │ ● LIVE · current context:build · last progress 2s ago     │
/// └──────────────────────────────────────────────────────────┘
/// ```
pub(crate) fn render_activity_view(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    paint_cinematic_background(frame.buffer_mut(), area);
    paint_cinematic_scanlines(frame.buffer_mut(), area);
    match activity_view_model(app) {
        ActivityViewModel::Active(activity) => {
            let phase = activity.phase_strip();
            render_active_activity_view(frame, area, &activity, phase.as_ref());
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

fn render_active_activity_view(
    frame: &mut Frame<'_>,
    area: Rect,
    activity: &ActiveActivityViewModel<'_>,
    phase: Option<&ActivityPhaseStripModel>,
) {
    let header_lines = activity_header_lines(activity, area.width);
    let phase_lines = phase
        .map(|model| activity_phase_strip_lines(model, area.width))
        .unwrap_or_default();
    // Footer height tracks the wrapped hint rows so narrow terminals get a
    // second hint line instead of keys clipped off the right edge.
    let footer = activity.footer(area.width);
    let footer_rows = (1 + footer.hint_rows.len().max(1)) as u16;
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header_lines.len() as u16),
            Constraint::Length(phase_lines.len() as u16),
            Constraint::Min(0),
            Constraint::Length(1),
            Constraint::Length(footer_rows),
        ])
        .split(area);

    render_header(frame, outer[0], header_lines);
    render_header(frame, outer[1], phase_lines);
    render_activity_panes(frame, outer[2], activity);
    render_activity_heartbeat(frame, outer[3], activity);
    render_focus_footer(frame, outer[4], activity);
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
    } else if area.width < SINGLE_PANE_BREAKPOINT {
        if pane_chrome.dag.focused {
            render_dag_pane_widget(frame, area, activity, &pane_chrome.dag);
        } else {
            render_feed_pane_widget(frame, area, activity, &pane_chrome.feed);
        }
    } else if area.height >= STACKED_PANE_MIN_HEIGHT {
        let panes = Layout::default()
            .direction(Direction::Vertical)
            .constraints(stacked_activity_pane_constraints(area.height))
            .split(area);
        render_feed_pane_widget(frame, panes[0], activity, &pane_chrome.feed);
        render_dag_pane_widget(frame, panes[1], activity, &pane_chrome.dag);
    } else {
        let panes = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(activity_pane_constraints(area.width, layout))
            .split(area);
        render_dag_pane_widget(frame, panes[0], activity, &pane_chrome.dag);
        render_feed_pane_widget(frame, panes[1], activity, &pane_chrome.feed);
    }
}

fn stacked_activity_pane_constraints(height: u16) -> [Constraint; 2] {
    let task_rows = (height / 3).max(12);
    [
        Constraint::Length(height.saturating_sub(task_rows)),
        Constraint::Min(12),
    ]
}

fn render_activity_heartbeat(
    frame: &mut Frame<'_>,
    area: Rect,
    activity: &ActiveActivityViewModel<'_>,
) {
    let model = activity.heartbeat(Instant::now());
    let style = match model.tone {
        ActivityHeartbeatTone::Live => theme::success(),
        ActivityHeartbeatTone::Stalled => theme::warn().add_modifier(Modifier::BOLD),
        ActivityHeartbeatTone::Complete => theme::muted(),
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            fit(&model.text, area.width as usize),
            style,
        ))),
        area,
    );
}

fn render_header(frame: &mut Frame<'_>, area: Rect, lines: Vec<Line<'static>>) {
    let para = Paragraph::new(lines);
    frame.render_widget(para, area);
}

fn activity_header_lines(activity: &ActiveActivityViewModel<'_>, width: u16) -> Vec<Line<'static>> {
    let model = activity.header();
    let title = if width < SINGLE_PANE_BREAKPOINT {
        model.compact_title
    } else {
        model.detailed_title
    };
    let mut lines = vec![
        Line::from(vec![Span::styled(
            fit(&title, width as usize),
            theme::heading(),
        )]),
        Line::from(vec![Span::styled(
            fit(activity.context_line(), width as usize),
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
