use super::dag_pane::{dag_row_text, dag_state_style, dag_subsystems_row_text};
use super::feed_pane::{feed_event_style, feed_event_text};
use super::*;
use crate::app::{ActivitySession, DagTaskState, PaneFocus};
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

    render_dag_pane_widget(frame, panes[0], session);
    render_feed_pane_widget(frame, panes[1], session);

    render_focus_footer(frame, outer[2], session);
}

fn render_header(frame: &mut Frame<'_>, area: Rect, session: &ActivitySession) {
    let total = session.tasks.len();
    let done = session
        .tasks
        .values()
        .filter(|row| matches!(row.state, DagTaskState::Done))
        .count();
    let running = session
        .tasks
        .values()
        .filter(|row| matches!(row.state, DagTaskState::Active))
        .count();
    let header = format!(
        "ACTIVITY  run {run}  ·  {done}/{total} done  ·  {running} running{paused}{verbose}",
        run = session.run_id,
        done = done,
        total = total,
        running = running,
        paused = if session.paused { "  ·  ⏸ paused" } else { "" },
        verbose = if session.verbose_subsystems {
            "  ·  V verbose"
        } else {
            ""
        },
    );
    let pane_label = match session.pane_focus {
        PaneFocus::Left => "[DAG focused]",
        PaneFocus::Right => "[FEED focused]",
    };
    let para = Paragraph::new(vec![
        Line::from(vec![Span::styled(header, theme::heading())]),
        Line::from(vec![Span::styled(
            pane_label.to_string(),
            theme::accent(),
        )]),
    ]);
    frame.render_widget(para, area);
}

fn render_dag_pane_widget(frame: &mut Frame<'_>, area: Rect, session: &ActivitySession) {
    let now = Instant::now();
    let inner_width = area.width.saturating_sub(2) as usize;
    let mut lines: Vec<Line<'static>> = Vec::new();
    for row in session.tasks.values() {
        let text = dag_row_text(row, inner_width, now);
        lines.push(Line::from(vec![Span::styled(text, dag_state_style(row.state))]));
    }
    if let Some(text) = dag_subsystems_row_text(session, inner_width) {
        lines.push(Line::from(vec![Span::styled(text, theme::muted())]));
    }
    if lines.is_empty() {
        lines.push(Line::from(vec![Span::styled(
            " (no DAG tasks yet)".to_string(),
            theme::muted(),
        )]));
    }

    let title_style = if matches!(session.pane_focus, PaneFocus::Left) {
        theme::accent()
    } else {
        theme::label()
    };
    let block = Block::default()
        .borders(Borders::RIGHT)
        .border_style(theme::subtle())
        .title(Span::styled(" DAG ", title_style));
    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    let scroll = clamp_scroll(session.task_scroll, lines.len(), inner_area.height as usize);
    let para = Paragraph::new(lines)
        .scroll((scroll as u16, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, inner_area);
}

fn render_feed_pane_widget(frame: &mut Frame<'_>, area: Rect, session: &ActivitySession) {
    let inner_width = area.width.saturating_sub(2) as usize;
    let mut lines: Vec<Line<'static>> = Vec::new();
    if session.paused {
        lines.push(Line::from(vec![Span::styled(
            " ⏸ paused — press p to resume".to_string(),
            theme::warn(),
        )]));
    }
    for event in session.events.iter() {
        if let Some(text) = feed_event_text(event, session.verbose_subsystems, inner_width) {
            lines.push(Line::from(vec![Span::styled(text, feed_event_style(event))]));
        }
    }
    if lines.is_empty() {
        // Distinguish "nothing has happened yet" from "events exist but are
        // all hidden subsystem activity (operator can press V)". Counts the
        // events the verbose filter is suppressing so the message is honest
        // about what the feed isn't showing.
        let hidden_count = session
            .events
            .iter()
            .filter(|event| {
                event
                    .step
                    .module_id
                    .as_deref()
                    .map(crate::app::is_hidden_module_id)
                    .unwrap_or(false)
            })
            .count();
        let placeholder = if hidden_count > 0 && !session.verbose_subsystems {
            format!(
                " ({hidden_count} hidden subsystem event{plural} — press V to show)",
                plural = if hidden_count == 1 { "" } else { "s" }
            )
        } else {
            " (waiting for trace events…)".to_string()
        };
        lines.push(Line::from(vec![Span::styled(placeholder, theme::muted())]));
    }

    let title_style = if matches!(session.pane_focus, PaneFocus::Right) {
        theme::accent()
    } else {
        theme::label()
    };
    let block = Block::default()
        .borders(Borders::NONE)
        .title(Span::styled(" FEED ", title_style));
    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    let scroll = if session.feed_auto_tail {
        // Auto-tail: scroll so the last `inner_height` lines are visible.
        let height = inner_area.height as usize;
        lines.len().saturating_sub(height)
    } else {
        // Operator pinned a position via manual scroll; honour it regardless
        // of whether the run is paused. `G` (scroll-to-bottom) resets
        // `feed_auto_tail = true` to return to live tailing.
        clamp_scroll(session.feed_scroll, lines.len(), inner_area.height as usize)
    };
    let para = Paragraph::new(lines)
        .scroll((scroll as u16, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, inner_area);
}

fn render_focus_footer(frame: &mut Frame<'_>, area: Rect, session: &ActivitySession) {
    let body = if let Some(task_id) = session.focus_task.as_ref() {
        if let Some(row) = session.tasks.get(task_id) {
            format!(
                " ▸ FOCUS  {task}  {state:?}  steps {n}  {label}",
                task = row.task_id,
                state = row.state,
                n = row.steps_done,
                label = row.last_label,
            )
        } else {
            format!(" ▸ FOCUS  {task_id}  (not yet recorded)")
        }
    } else {
        " ▸ FOCUS  hover j/k to inspect a task · Tab pane · V verbose · p pause · R reset · Enter focus"
            .to_string()
    };
    let keys = Line::from(vec![Span::styled(
        " j/k scroll · Tab pane · V verbose · p pause · R reset · Enter focus".to_string(),
        theme::muted(),
    )]);
    let lines = vec![
        Line::from(vec![Span::styled(body, theme::label())]),
        keys,
    ];
    let para = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

fn clamp_scroll(requested: usize, total: usize, viewport: usize) -> usize {
    if total <= viewport {
        return 0;
    }
    let max = total.saturating_sub(viewport);
    requested.min(max)
}
