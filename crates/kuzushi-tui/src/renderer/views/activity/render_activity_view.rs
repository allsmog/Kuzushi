use super::dag_pane::dag_row_style;
use super::feed_pane::feed_row_style;
use super::*;
use crate::ui_view_models::{
    activity_view_model, ActivityFooterHint, ActivityHeartbeatTone, ActivityPaneLayout,
    ActivityPaneTitle, ActivityViewModel, RunFocusModel,
};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Frame, Line, Span};
use ratatui::style::Modifier;
use ratatui::widgets::{Paragraph, Wrap};
use std::time::Instant;

const SINGLE_PANE_BREAKPOINT: u16 = 50;

/// Render Run Focus as one run-owned surface with adaptive Steps and Output
/// panes plus one authoritative health line in the header.
///
/// Layout (within `area`):
///
/// ```text
/// ┌─ header (1 row) ──────────────────────────────────────────┐
/// │ RUN FOCUS  run r-... · 11/14 done · 2 running             │
/// ├──────────────────────────────────────────────────────────┤
/// │ ┌─ OUTPUT ─────────┬─ TASKS ──────────────────────────┐  │
/// │ │ build trace      │ ✓ context:build                 │  │
/// │ │ ▸ map surface    │ 15:09:39 [context:build]        │  │
/// │ │ · write snapshot │ 15:09:42 stage 4/6             │  │
/// │ └──────────────────┴──────────────────────────────────┘  │
/// │ ● LIVE · current context:build · last progress 2s ago     │
/// └──────────────────────────────────────────────────────────┘
/// ```
pub(crate) fn render_activity_view(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    paint_cinematic_background(frame.buffer_mut(), area);
    paint_cinematic_scanlines(frame.buffer_mut(), area);
    match activity_view_model(app) {
        ActivityViewModel::Active(activity) => {
            render_active_activity_view(frame, area, &activity);
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

fn render_active_activity_view(frame: &mut Frame<'_>, area: Rect, activity: &RunFocusModel<'_>) {
    let now = Instant::now();
    let (heartbeat, heartbeat_rows) = activity.heartbeat_rows(area.width, now);
    let heartbeat_row_count = heartbeat_rows.len();
    let header_lines = activity_header_lines(activity, area.width, heartbeat, heartbeat_rows);
    let footer_lines = focus_footer_lines(area.width, activity);
    let geometry = activity.frame_layout(area.width, heartbeat_row_count);
    debug_assert_eq!(header_lines.len(), usize::from(geometry.header_rows));
    debug_assert_eq!(footer_lines.len(), usize::from(geometry.footer_rows));
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(geometry.header_rows),
            Constraint::Min(0),
            Constraint::Length(geometry.footer_rows),
        ])
        .split(area);

    render_header(frame, outer[0], header_lines);
    render_activity_panes(frame, outer[1], activity, now);
    render_focus_footer(frame, outer[2], footer_lines);
}

fn render_activity_panes(
    frame: &mut Frame<'_>,
    area: Rect,
    activity: &RunFocusModel<'_>,
    now: Instant,
) {
    let pane_chrome = activity.pane_chrome();
    if activity.collapse_dag_pane() {
        render_feed_pane_widget(frame, area, activity, &pane_chrome.feed);
        return;
    }
    match activity.pane_layout(area.width, area.height, now) {
        ActivityPaneLayout::Focused => {
            render_focused_activity_pane(frame, area, activity, &pane_chrome, now)
        }
        ActivityPaneLayout::Stacked { task_height } => {
            render_stacked_activity_panes(frame, area, activity, &pane_chrome, task_height, now)
        }
        ActivityPaneLayout::SideBySide { task_width } => {
            render_side_by_side_activity_panes(frame, area, activity, &pane_chrome, task_width, now)
        }
    }
}

fn render_stacked_activity_panes(
    frame: &mut Frame<'_>,
    area: Rect,
    activity: &RunFocusModel<'_>,
    pane_chrome: &crate::ui_view_models::ActivityPaneChromeModel,
    task_height: u16,
    now: Instant,
) {
    let panes = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(task_height), Constraint::Min(3)])
        .split(area);
    let task_lines = dag_pane_lines(activity, inner_width(panes[0]), now);
    render_dag_pane_widget(frame, panes[0], activity, &pane_chrome.dag, task_lines);
    render_feed_pane_widget(frame, panes[1], activity, &pane_chrome.feed);
}

fn render_side_by_side_activity_panes(
    frame: &mut Frame<'_>,
    area: Rect,
    activity: &RunFocusModel<'_>,
    pane_chrome: &crate::ui_view_models::ActivityPaneChromeModel,
    task_width: u16,
    now: Instant,
) {
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(task_width), Constraint::Min(48)])
        .split(area);
    let task_lines = dag_pane_lines(activity, inner_width(panes[0]), now);
    render_dag_pane_widget(frame, panes[0], activity, &pane_chrome.dag, task_lines);
    render_feed_pane_widget(frame, panes[1], activity, &pane_chrome.feed);
}

fn render_focused_activity_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    activity: &RunFocusModel<'_>,
    chrome: &crate::ui_view_models::ActivityPaneChromeModel,
    now: Instant,
) {
    if chrome.dag.focused {
        let task_lines = dag_pane_lines(activity, inner_width(area), now);
        render_dag_pane_widget(frame, area, activity, &chrome.dag, task_lines);
    } else {
        render_feed_pane_widget(frame, area, activity, &chrome.feed);
    }
}

fn inner_width(area: Rect) -> usize {
    area.width.saturating_sub(2) as usize
}

fn render_header(frame: &mut Frame<'_>, area: Rect, lines: Vec<Line<'static>>) {
    let para = Paragraph::new(lines);
    frame.render_widget(para, area);
}

fn activity_header_lines(
    activity: &RunFocusModel<'_>,
    width: u16,
    health: crate::ui_view_models::ActivityHeartbeatModel,
    health_rows: Vec<String>,
) -> Vec<Line<'static>> {
    let model = activity.header();
    let title = if width < SINGLE_PANE_BREAKPOINT {
        model.compact_title.as_str()
    } else {
        model.detailed_title.as_str()
    };
    let mut lines = vec![
        activity_title_line(&model, &title, width as usize),
        Line::from(vec![Span::styled(
            fit(activity.context_line(), width as usize),
            theme::muted(),
        )]),
    ];
    if let Some(banner) = activity.abort_banner() {
        lines.push(Line::from(vec![Span::styled(banner, theme::warn())]));
    }
    let style = match health.tone {
        ActivityHeartbeatTone::Live => theme::success(),
        ActivityHeartbeatTone::Stalled => theme::warn().add_modifier(Modifier::BOLD),
        ActivityHeartbeatTone::Complete => theme::muted(),
        ActivityHeartbeatTone::Warning => theme::warn(),
        ActivityHeartbeatTone::Failed => theme::danger().add_modifier(Modifier::BOLD),
    };
    lines.extend(
        health_rows
            .into_iter()
            .map(|row| Line::from(Span::styled(row, style))),
    );
    lines
}

fn activity_title_line(
    model: &crate::ui_view_models::ActivityHeaderModel,
    title: &str,
    width: usize,
) -> Line<'static> {
    let Some(phase) = model.origin_phase else {
        return Line::from(Span::styled(fit(title, width), theme::heading()));
    };
    let token = format!("RUN FOCUS · {}", phase.label());
    let suffix = title.strip_prefix(&token).unwrap_or_default();
    let prefix = "RUN FOCUS · ";
    let suffix_width = width.saturating_sub(prefix.chars().count() + phase.label().chars().count());
    Line::from(vec![
        Span::styled(prefix, theme::heading()),
        Span::styled(phase.label(), activity_phase_style(phase)),
        Span::styled(fit(suffix, suffix_width), theme::heading()),
    ])
}

fn activity_phase_style(phase: kuzushi_core::WorkflowPhase) -> ratatui::style::Style {
    match phase {
        kuzushi_core::WorkflowPhase::Map => theme::mode_map(),
        kuzushi_core::WorkflowPhase::Scan => theme::mode_scan(),
        kuzushi_core::WorkflowPhase::Review => theme::mode_review(),
        kuzushi_core::WorkflowPhase::Prove => theme::mode_prove(),
        kuzushi_core::WorkflowPhase::Fix => theme::mode_fix(),
    }
}

fn render_dag_pane_widget(
    frame: &mut Frame<'_>,
    area: Rect,
    activity: &RunFocusModel<'_>,
    title: &ActivityPaneTitle,
    lines: Vec<Line<'static>>,
) {
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
    activity: &RunFocusModel<'_>,
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
    activity: &RunFocusModel<'_>,
    title: &ActivityPaneTitle,
) {
    let block = cockpit_pane_block(
        Line::from(Span::styled(
            title.block_title.clone(),
            pane_title_style(title),
        )),
        title.focused,
    );
    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    let lines = feed_pane_lines(
        activity,
        inner_area.width as usize,
        inner_area.height as usize,
    );
    let para = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(para, inner_area);
}

fn pane_title_style(title: &ActivityPaneTitle) -> ratatui::style::Style {
    if title.focused {
        return theme::accent().add_modifier(Modifier::BOLD);
    }
    theme::muted()
}

fn feed_pane_lines(
    activity: &RunFocusModel<'_>,
    inner_width: usize,
    inner_height: usize,
) -> Vec<Line<'static>> {
    activity
        .feed_pane_viewport_rows(inner_width, inner_height)
        .into_iter()
        .map(|row| {
            let _source_key = &row.key;
            let _disclosed_source_keys = &row.disclosed_keys;
            Line::from(vec![Span::styled(row.text, feed_row_style(row.tone))])
        })
        .collect()
}

fn render_focus_footer(frame: &mut Frame<'_>, area: Rect, lines: Vec<Line<'static>>) {
    let para = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

fn focus_footer_lines(width: u16, activity: &RunFocusModel<'_>) -> Vec<Line<'static>> {
    let footer = activity.footer(width);
    let mut lines = Vec::new();
    if let Some(editor) = footer.steer_line {
        lines.push(Line::from(vec![Span::styled(
            fit(&editor, width as usize),
            theme::accent(),
        )]));
    }
    if let Some(error) = footer.steer_error {
        lines.push(Line::from(vec![Span::styled(
            fit(&format!(" ⚠ {error}"), width as usize),
            theme::warn(),
        )]));
    }
    lines.push(Line::from(vec![Span::styled(
        footer.body_line,
        theme::label(),
    )]));
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
    spans.push(Span::styled(hint.full_key_text.clone(), theme::accent()));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(hint.full_hint_text.clone(), theme::muted()));
}
