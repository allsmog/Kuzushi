use super::activity_feed_rows::{
    activity_feed_pane_rows, ActivityFeedPaneRow, ActivityFeedRowTone,
};
use crate::theme::{self, ThemeConfig};
use crate::{ActivitySession, DagTaskDetail, DagTaskDetailState, DagTaskRow, DagTaskState};
use std::sync::OnceLock;
use std::time::Instant;

const MAX_TASK_PANE_ACTION_ROWS: usize = 8;
const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

static SPINNER_EPOCH: OnceLock<Instant> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActivityDagRowTone {
    Done,
    Active,
    Queued,
    Failing,
    Canceled,
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
    running_tool: Option<&str>,
) -> Vec<ActivityDagPaneRow> {
    let mut rows = session
        .tasks
        .values()
        .flat_map(|row| task_pane_rows(session, row, width, now))
        .collect::<Vec<_>>();
    if let Some(text) = dag_subsystems_row_text(session, width) {
        rows.push(ActivityDagPaneRow {
            text,
            tone: subsystem_row_tone(session.subsystem_aggregate.state),
        });
    }
    rows.extend(action_pane_rows(session, width, running_tool));
    if rows.is_empty() {
        rows.push(ActivityDagPaneRow {
            text: " (no DAG tasks yet)".to_string(),
            tone: ActivityDagRowTone::Muted,
        });
    }
    rows
}

fn action_pane_rows(
    session: &ActivitySession,
    width: usize,
    running_tool: Option<&str>,
) -> Vec<ActivityDagPaneRow> {
    let feed_width = width.saturating_sub(5).max(16);
    let feed_rows = latest_action_rows(activity_feed_pane_rows(session, feed_width, running_tool));
    if feed_rows.is_empty() {
        return Vec::new();
    }
    let mut rows = vec![ActivityDagPaneRow {
        text: fit("  ACTIONS", width),
        tone: ActivityDagRowTone::Muted,
    }];
    rows.extend(feed_rows.into_iter().map(|row| ActivityDagPaneRow {
        text: fit(&format!("     {}", row.text.trim_start()), width),
        tone: action_row_tone(row.tone),
    }));
    rows
}

fn latest_action_rows(rows: Vec<ActivityFeedPaneRow>) -> Vec<ActivityFeedPaneRow> {
    if rows.len() <= MAX_TASK_PANE_ACTION_ROWS {
        return rows;
    }
    let first_visible = rows.len().saturating_sub(MAX_TASK_PANE_ACTION_ROWS);
    rows.into_iter().skip(first_visible).collect()
}

fn action_row_tone(tone: ActivityFeedRowTone) -> ActivityDagRowTone {
    match tone {
        ActivityFeedRowTone::Primary => ActivityDagRowTone::Active,
        ActivityFeedRowTone::Success => ActivityDagRowTone::Done,
        ActivityFeedRowTone::Danger => ActivityDagRowTone::Failing,
        ActivityFeedRowTone::Warn => ActivityDagRowTone::Failing,
        ActivityFeedRowTone::Muted | ActivityFeedRowTone::Subtle => ActivityDagRowTone::Muted,
    }
}

fn dag_row_tone(state: DagTaskState) -> ActivityDagRowTone {
    match state {
        DagTaskState::Done => ActivityDagRowTone::Done,
        DagTaskState::Active => ActivityDagRowTone::Active,
        DagTaskState::Queued => ActivityDagRowTone::Queued,
        DagTaskState::Failing => ActivityDagRowTone::Failing,
        DagTaskState::Canceled => ActivityDagRowTone::Canceled,
    }
}

fn spinner_frame(now: Instant) -> &'static str {
    spinner_frame_for_config(now, theme::active_theme())
}

fn spinner_frame_for_config(now: Instant, config: ThemeConfig) -> &'static str {
    if config.reduced_motion {
        return SPINNER_FRAMES[0];
    }
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
        DagTaskState::Canceled => "×",
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

/// A task's row, plus — under a running task — a sub-line showing what it's
/// doing right now (its latest sub-step), so the operator sees the work inside.
fn task_pane_rows(
    session: &ActivitySession,
    row: &DagTaskRow,
    width: usize,
    now: Instant,
) -> Vec<ActivityDagPaneRow> {
    let mut out = vec![ActivityDagPaneRow {
        text: dag_row_text(row, width, now),
        tone: dag_row_tone(row.state),
    }];
    if should_show_task_details(session, row) {
        out.extend(task_detail_rows(row, width));
    } else if let Some(text) = dag_active_substep_text(row, width) {
        out.push(ActivityDagPaneRow {
            text,
            tone: ActivityDagRowTone::Muted,
        });
    }
    out
}

fn should_show_task_details(session: &ActivitySession, row: &DagTaskRow) -> bool {
    !row.details.is_empty()
        && (row.state == DagTaskState::Active
            || session.focus_task.as_deref() == Some(row.task_id.as_str()))
}

fn task_detail_rows(row: &DagTaskRow, width: usize) -> Vec<ActivityDagPaneRow> {
    row.details
        .iter()
        .map(|detail| ActivityDagPaneRow {
            text: dag_detail_text(detail, width),
            tone: dag_detail_tone(detail.state),
        })
        .collect()
}

fn dag_detail_text(detail: &DagTaskDetail, width: usize) -> String {
    let symbol = match detail.state {
        DagTaskDetailState::Active => "↳",
        DagTaskDetailState::Done => "✓",
        DagTaskDetailState::Failing => "!",
        DagTaskDetailState::Canceled => "×",
    };
    fit(
        &format!("     {symbol} {}{}", detail.label, detail.meta),
        width,
    )
}

fn dag_detail_tone(state: DagTaskDetailState) -> ActivityDagRowTone {
    match state {
        DagTaskDetailState::Active => ActivityDagRowTone::Active,
        DagTaskDetailState::Done => ActivityDagRowTone::Muted,
        DagTaskDetailState::Failing => ActivityDagRowTone::Failing,
        DagTaskDetailState::Canceled => ActivityDagRowTone::Canceled,
    }
}

fn dag_active_substep_text(row: &DagTaskRow, width: usize) -> Option<String> {
    if row.state != DagTaskState::Active {
        return None;
    }
    let label = row.last_label.trim();
    if label.is_empty() {
        return None;
    }
    Some(fit(&format!("     ↳ {label}"), width))
}

fn dag_subsystems_row_text(session: &ActivitySession, width: usize) -> Option<String> {
    let agg = &session.subsystem_aggregate;
    if agg.total_count == 0 {
        return None;
    }
    let label = fit(&agg.last_label, width.saturating_sub(28).max(8));
    Some(fit(
        &format!(
            " ⤳ subsystems ({total})  {state} {label}",
            total = agg.total_count,
            state = subsystem_state_label(agg.state),
            label = label,
        ),
        width,
    ))
}

fn subsystem_row_tone(state: DagTaskState) -> ActivityDagRowTone {
    match state {
        DagTaskState::Failing => ActivityDagRowTone::Failing,
        DagTaskState::Active => ActivityDagRowTone::Active,
        DagTaskState::Done => ActivityDagRowTone::Done,
        DagTaskState::Canceled => ActivityDagRowTone::Canceled,
        DagTaskState::Queued => ActivityDagRowTone::Muted,
    }
}

fn subsystem_state_label(state: DagTaskState) -> &'static str {
    match state {
        DagTaskState::Failing => "failing",
        DagTaskState::Active => "active",
        DagTaskState::Done => "done",
        DagTaskState::Canceled => "canceled",
        DagTaskState::Queued => "queued",
    }
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
    use crate::{DagTaskDetail, DagTaskDetailState, SubsystemAggregate};
    use kuzushi_core::RunTraceStep;

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
        session.subsystem_aggregate =
            SubsystemAggregate::test_seeded(2, "preflight", DagTaskState::Queued);

        let rows = activity_dag_pane_rows(&session, 40, Instant::now(), None);

        assert_eq!(rows.len(), 4);
        assert!(rows[0].text.contains("semgrep:scan"));
        assert_eq!(rows[0].tone, ActivityDagRowTone::Queued);
        assert!(rows[1].text.contains("subsystems (2)"));
        assert_eq!(rows[1].tone, ActivityDagRowTone::Muted);
        assert!(rows[2].text.contains("ACTIONS"));
        assert!(rows[3].text.contains("no trace events"));
    }

    #[test]
    fn subsystem_row_turns_failing_on_hidden_module_error() {
        let mut session = ActivitySession::new("r-1");
        session.apply_step(
            RunTraceStep::new(1, "refused", "pipeline failed")
                .with_module_id("pipeline")
                .with_verb("prepare")
                .with_severity("danger"),
        );

        let rows = activity_dag_pane_rows(&session, 60, Instant::now(), None);

        assert!(rows[0].text.contains("subsystems (1)"));
        assert!(rows[0].text.contains("failing"));
        assert_eq!(rows[0].tone, ActivityDagRowTone::Failing);
    }

    #[test]
    fn activity_dag_pane_rows_supplies_empty_state() {
        let session = ActivitySession::new("r-1");

        let rows = activity_dag_pane_rows(&session, 40, Instant::now(), None);

        assert_eq!(rows.len(), 2);
        assert!(rows[0].text.contains("ACTIONS"));
        assert!(rows[1].text.contains("no trace events"));
    }

    #[test]
    fn activity_dag_pane_rows_expands_active_task_details() {
        let mut session = ActivitySession::new("r-1");
        let mut row = DagTaskRow::queued(
            "agentic-sast:scan".to_string(),
            "agentic-sast".to_string(),
            vec![],
        );
        row.state = DagTaskState::Active;
        row.details = vec![
            DagTaskDetail {
                label: "inventory-review".to_string(),
                kind: "reasoning".to_string(),
                state: DagTaskDetailState::Done,
                meta: String::new(),
            },
            DagTaskDetail {
                label: "vulnerability-hunt".to_string(),
                kind: "reasoning".to_string(),
                state: DagTaskDetailState::Active,
                meta: " (2.4s · $0.0123)".to_string(),
            },
        ];
        session.tasks.insert(row.task_id.clone(), row);

        let rows = activity_dag_pane_rows(&session, 80, Instant::now(), None);

        assert_eq!(rows.len(), 5);
        assert!(rows[0].text.contains("agentic-sast:scan"));
        assert!(rows[1].text.contains("✓ inventory-review"));
        assert_eq!(rows[1].tone, ActivityDagRowTone::Muted);
        assert!(rows[2].text.contains("↳ vulnerability-hunt"));
        assert!(rows[2].text.contains("2.4s"));
        assert_eq!(rows[2].tone, ActivityDagRowTone::Active);
        assert!(rows[3].text.contains("ACTIONS"));
        assert!(rows[4].text.contains("no trace events"));
    }

    #[test]
    fn spinner_frame_respects_reduced_motion() {
        let now = Instant::now();
        let reduced = ThemeConfig {
            reduced_motion: true,
            ..ThemeConfig::default()
        };
        let animated = ThemeConfig {
            reduced_motion: false,
            ..ThemeConfig::default()
        };

        assert_eq!(spinner_frame_for_config(now, reduced), SPINNER_FRAMES[0]);
        assert!(SPINNER_FRAMES.contains(&spinner_frame_for_config(now, animated)));
    }

    #[test]
    fn activity_dag_pane_rows_tails_latest_actions() {
        let mut session = ActivitySession::new("r-1");
        for index in 0..12 {
            session.apply_step(
                RunTraceStep::new(index + 1, "reasoning", format!("event {index}"))
                    .with_module_id("triage")
                    .with_verb("run")
                    .with_started_at_ms(42_000 + index as u64),
            );
        }

        let rows = activity_dag_pane_rows(&session, 80, Instant::now(), None);

        assert_eq!(
            rows.iter()
                .filter(|row| row.text.contains("[triage:run]"))
                .count(),
            MAX_TASK_PANE_ACTION_ROWS
        );
        assert!(rows.iter().all(|row| !row.text.contains("event 3")));
        assert!(rows.iter().any(|row| row.text.contains("event 4")));
        assert!(rows.last().unwrap().text.contains("event 11"));
    }
}
