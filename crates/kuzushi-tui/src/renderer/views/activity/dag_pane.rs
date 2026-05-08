use super::*;
use crate::app::{ActivitySession, DagTaskRow, DagTaskState};
use std::time::Instant;

/// Render one DAG task row as plain text (no styling). The renderer turns each
/// String into a styled span downstream so we keep the column-width math here
/// in one place.
pub(crate) fn dag_row_text(row: &DagTaskRow, width: usize, now: Instant) -> String {
    let symbol = match row.state {
        DagTaskState::Done => "✓",
        DagTaskState::Active => "▸",
        DagTaskState::Queued => "·",
        DagTaskState::Failing => "!",
    };
    let task_label = fit(&row.task_id, width.saturating_sub(20).max(8));
    let elapsed = elapsed_label(row, now);
    let status = match row.state {
        DagTaskState::Done => "done",
        DagTaskState::Active => "running",
        DagTaskState::Queued => "queued",
        DagTaskState::Failing => "failing",
    };
    // Pad columns: ` <symbol> <task pad-32> <elapsed pad-8>  <status>`
    let body = format!(
        " {symbol} {task:<task_pad$} {elapsed:>8}  {status}",
        symbol = symbol,
        task = task_label,
        task_pad = width.saturating_sub(20).max(8),
        elapsed = elapsed,
        status = status,
    );
    fit(&body, width)
}

pub(crate) fn dag_subsystems_row_text(session: &ActivitySession, width: usize) -> Option<String> {
    let agg = &session.subsystem_aggregate;
    if agg.total_count == 0 {
        return None;
    }
    let label = fit(&agg.last_label, width.saturating_sub(28).max(8));
    Some(fit(
        &format!(
            " ⤳ subsystems ({total})  {label}",
            total = agg.total_count,
            label = label,
        ),
        width,
    ))
}

pub(crate) fn dag_state_style(state: DagTaskState) -> ratatui::style::Style {
    match state {
        DagTaskState::Done => theme::success(),
        DagTaskState::Active => theme::warn(),
        DagTaskState::Queued => theme::muted(),
        DagTaskState::Failing => theme::danger(),
    }
}

fn elapsed_label(row: &DagTaskRow, now: Instant) -> String {
    let started = match row.started_at {
        Some(t) => t,
        None => return "-".to_string(),
    };
    let end = row.completed_at.unwrap_or(now);
    let secs = end.saturating_duration_since(started).as_secs_f64();
    if secs >= 60.0 {
        format!("{:.0}m{:02.0}s", (secs / 60.0).floor(), secs % 60.0)
    } else if secs >= 10.0 {
        format!("{secs:>4.1}s")
    } else {
        format!("{secs:>4.2}s")
    }
}
