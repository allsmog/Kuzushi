use super::dag_pane::{dag_row_text, dag_state_style, dag_subsystems_row_text};
use super::feed_pane::{feed_event_style, feed_event_text};
use super::*;
use crate::app::PaneFocus;
use std::time::Instant;

/// Build the line list for the Activity view. Renders a split-pane layout:
///   left ~46% — DAG status rows (one row per visible task + subsystems aggregate)
///   right ~54% — chronological reasoning feed `[module:verb] label`
///   footer    — single-line focus pane summary
pub(crate) fn activity_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());

    let Some(session) = app.activity.as_ref() else {
        lines.push(divider("ACTIVITY", area.width));
        lines.push(muted(
            "(no run active; start one with `scan` or `run <tool>` and the feed will appear here)",
        ));
        return lines;
    };

    let total = session.tasks.len();
    let done = session
        .tasks
        .values()
        .filter(|t| matches!(t.state, crate::app::DagTaskState::Done))
        .count();
    let running = session
        .tasks
        .values()
        .filter(|t| matches!(t.state, crate::app::DagTaskState::Active))
        .count();
    let header = format!(
        "ACTIVITY  run {run}  ·  {done}/{total} done  ·  {running} running",
        run = session.run_id,
        done = done,
        total = total,
        running = running,
    );
    lines.push(divider(&header, area.width));

    let total_width = area.width as usize;
    // Reserve 1 column for divider, split the rest 46% / 54%.
    let usable = total_width.saturating_sub(1);
    let left_w = (usable * 46 / 100).max(20);
    let right_w = usable.saturating_sub(left_w).max(20);

    // Header row showing pane labels.
    lines.push(pane_header_line(
        "DAG",
        "FEED",
        left_w,
        right_w,
        session.pane_focus,
    ));

    let now = Instant::now();
    let mut left_rows: Vec<(String, ratatui::style::Style)> = Vec::new();
    for row in session.tasks.values() {
        let text = dag_row_text(row, left_w, now);
        left_rows.push((text, dag_state_style(row.state)));
    }
    if let Some(text) = dag_subsystems_row_text(session, left_w) {
        left_rows.push((text, theme::muted()));
    }

    let mut right_rows: Vec<(String, ratatui::style::Style)> = Vec::new();
    for event in session.events.iter() {
        if let Some(text) = feed_event_text(event, session.verbose_subsystems, right_w) {
            right_rows.push((text, feed_event_style(event)));
        }
    }
    // Pause marker: when paused, prepend a sentinel row at the head of the
    // feed so the operator notices the freeze.
    if session.paused {
        right_rows.insert(
            0,
            (
                fit("⏸ paused — press p to resume", right_w),
                theme::warn(),
            ),
        );
    }

    let max_rows = left_rows.len().max(right_rows.len());
    for i in 0..max_rows {
        let (left_text, left_style) = left_rows
            .get(i)
            .cloned()
            .unwrap_or((" ".repeat(left_w), theme::primary()));
        let (right_text, right_style) = right_rows
            .get(i)
            .cloned()
            .unwrap_or((String::new(), theme::primary()));
        lines.push(combined_pane_line(
            left_text,
            left_style,
            right_text,
            right_style,
            left_w,
            right_w,
        ));
    }

    lines.push(blank());
    lines.push(focus_footer_line(session, area.width));
    lines.push(keybind_hint_line(&[
        ("j/k", "scroll"),
        ("Tab", "switch pane"),
        ("V", "verbose"),
        ("p", "pause"),
        ("R", "reset"),
        ("Enter", "focus task"),
    ]));
    lines
}

fn pane_header_line(
    left: &str,
    right: &str,
    left_w: usize,
    right_w: usize,
    focus: PaneFocus,
) -> Line<'static> {
    let left_style = if matches!(focus, PaneFocus::Left) {
        theme::accent()
    } else {
        theme::label()
    };
    let right_style = if matches!(focus, PaneFocus::Right) {
        theme::accent()
    } else {
        theme::label()
    };
    let left_pad = format!(" ── {left} ");
    let right_pad = format!(" ── {right} ");
    Line::from(vec![
        Span::styled(pad_to(&left_pad, left_w), left_style),
        Span::styled("│".to_string(), theme::subtle()),
        Span::styled(pad_to(&right_pad, right_w), right_style),
    ])
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

fn focus_footer_line(session: &crate::app::ActivitySession, width: u16) -> Line<'static> {
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
        " ▸ FOCUS  hover j/k to inspect a task · Tab pane · V verbose · p pause · R reset".to_string()
    };
    Line::from(vec![Span::styled(
        fit(&body, width as usize),
        theme::label(),
    )])
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
