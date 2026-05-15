use crate::{ActivitySession, DagTaskRow, DagTaskState};
use std::sync::OnceLock;
use std::time::Instant;

const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

static SPINNER_EPOCH: OnceLock<Instant> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActivityDagRowTone {
    Done,
    Active,
    Queued,
    Failing,
    Muted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityDagPaneRow {
    pub(crate) text: String,
    pub(crate) tone: ActivityDagRowTone,
}

pub(crate) fn activity_dag_pane_rows(
    session: &ActivitySession,
    width: usize,
    now: Instant,
) -> Vec<ActivityDagPaneRow> {
    let mut rows = session
        .tasks
        .values()
        .map(|row| ActivityDagPaneRow {
            text: dag_row_text(row, width, now),
            tone: dag_row_tone(row.state),
        })
        .collect::<Vec<_>>();
    if let Some(text) = dag_subsystems_row_text(session, width) {
        rows.push(ActivityDagPaneRow {
            text,
            tone: ActivityDagRowTone::Muted,
        });
    }
    if rows.is_empty() {
        rows.push(ActivityDagPaneRow {
            text: " (no DAG tasks yet)".to_string(),
            tone: ActivityDagRowTone::Muted,
        });
    }
    rows
}

fn dag_row_tone(state: DagTaskState) -> ActivityDagRowTone {
    match state {
        DagTaskState::Done => ActivityDagRowTone::Done,
        DagTaskState::Active => ActivityDagRowTone::Active,
        DagTaskState::Queued => ActivityDagRowTone::Queued,
        DagTaskState::Failing => ActivityDagRowTone::Failing,
    }
}

fn spinner_frame(now: Instant) -> &'static str {
    let epoch = SPINNER_EPOCH.get_or_init(Instant::now);
    let ms = now
        .checked_duration_since(*epoch)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let idx = ((ms / 100) as usize) % SPINNER_FRAMES.len();
    SPINNER_FRAMES[idx]
}

fn dag_row_text(row: &DagTaskRow, width: usize, now: Instant) -> String {
    let symbol = match row.state {
        DagTaskState::Done => "✓",
        DagTaskState::Active => spinner_frame(now),
        DagTaskState::Queued => "·",
        DagTaskState::Failing => "!",
    };
    let right_reserve: usize = 9;
    let task_pad = width.saturating_sub(right_reserve + 3).max(8);
    let task_label = fit(&row.task_id, task_pad);
    let elapsed = elapsed_label(row, now);
    let body = format!(
        " {symbol} {task:<task_pad$} {elapsed:>8}",
        symbol = symbol,
        task = task_label,
        task_pad = task_pad,
        elapsed = elapsed,
    );
    fit(&body, width)
}

fn dag_subsystems_row_text(session: &ActivitySession, width: usize) -> Option<String> {
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

fn elapsed_label(row: &DagTaskRow, now: Instant) -> String {
    let started = match row.started_at {
        Some(t) => t,
        None => return "-".to_string(),
    };
    let end = row.completed_at.unwrap_or(now);
    let elapsed = end.saturating_duration_since(started);
    let secs = elapsed.as_secs_f64();
    if secs >= 60.0 {
        format!("{:.0}m{:02.0}s", (secs / 60.0).floor(), secs % 60.0)
    } else if secs >= 10.0 {
        format!("{secs:>4.1}s")
    } else if secs >= 1.0 {
        format!("{secs:>4.2}s")
    } else {
        let ms = elapsed.as_millis();
        if ms == 0 {
            "  <1ms".to_string()
        } else if ms < 1000 {
            format!("{ms:>4}ms")
        } else {
            format!("{secs:>4.2}s")
        }
    }
}

fn fit(value: &str, width: usize) -> String {
    let len = value.chars().count();
    if len <= width {
        return value.to_string();
    }
    if width <= 1 {
        return value.chars().take(width).collect();
    }
    format!("{}…", value.chars().take(width - 1).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SubsystemAggregate;

    #[test]
    fn activity_dag_pane_rows_projects_tasks_and_subsystems() {
        let mut session = ActivitySession::new("r-1");
        session.tasks.insert(
            "semgrep:scan".to_string(),
            DagTaskRow::queued(
                "semgrep:scan".to_string(),
                "semgrep".to_string(),
                Vec::new(),
            ),
        );
        session.subsystem_aggregate = SubsystemAggregate {
            active_count: 0,
            total_count: 2,
            last_label: "preflight".to_string(),
        };

        let rows = activity_dag_pane_rows(&session, 40, Instant::now());

        assert_eq!(rows.len(), 2);
        assert!(rows[0].text.contains("semgrep:scan"));
        assert_eq!(rows[0].tone, ActivityDagRowTone::Queued);
        assert!(rows[1].text.contains("subsystems (2)"));
        assert_eq!(rows[1].tone, ActivityDagRowTone::Muted);
    }

    #[test]
    fn activity_dag_pane_rows_supplies_empty_state() {
        let session = ActivitySession::new("r-1");

        let rows = activity_dag_pane_rows(&session, 40, Instant::now());

        assert_eq!(
            rows,
            vec![ActivityDagPaneRow {
                text: " (no DAG tasks yet)".to_string(),
                tone: ActivityDagRowTone::Muted,
            }]
        );
    }
}
