use crate::theme::{self, ThemeConfig};
use crate::{
    ActivityRouteState, ActivitySession, DagTaskDetail, DagTaskDetailState, DagTaskRow,
    DagTaskState,
};
use std::sync::OnceLock;
use std::time::Instant;

const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

static SPINNER_EPOCH: OnceLock<Instant> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActivityDagRowTone {
    Done,
    Active,
    Queued,
    Warning,
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
    route: &ActivityRouteState,
    width: usize,
    now: Instant,
    running_tool: Option<&str>,
) -> Vec<ActivityDagPaneRow> {
    let mut rows = task_status_rows(session, route, width, now);
    append_subsystem_row(&mut rows, session, route, width);
    append_task_legend_row(&mut rows, session, width);
    append_taskless_live_row(&mut rows, session, route, running_tool);
    ensure_activity_rows(rows)
}

fn task_status_rows(
    session: &ActivitySession,
    route: &ActivityRouteState,
    width: usize,
    now: Instant,
) -> Vec<ActivityDagPaneRow> {
    let hidden_not_run = (!route.verbose_subsystems)
        .then(|| {
            session
                .tasks
                .values()
                .filter(|row| {
                    activity_row_is_never_started(row)
                        && !session.task_is_sequence_owned(&row.task_id)
                })
                .count()
        })
        .unwrap_or(0);
    let mut rows = session
        .ordered_task_rows()
        .into_iter()
        .enumerate()
        .filter(|(_, row)| {
            route.verbose_subsystems
                || !activity_row_is_never_started(row)
                || session.task_is_sequence_owned(&row.task_id)
        })
        .flat_map(|(index, row)| task_pane_rows(route, row, index, width, now))
        .collect::<Vec<_>>();
    if hidden_not_run > 0 {
        rows.push(ActivityDagPaneRow {
            text: fit(
                &format!("  {hidden_not_run} not run · V shows tasks"),
                width,
            ),
            tone: ActivityDagRowTone::Muted,
        });
    }
    rows
}

fn activity_row_is_never_started(row: &DagTaskRow) -> bool {
    row.state == DagTaskState::Queued
        || (row.state == DagTaskState::Skipped && row.started_at.is_none())
}

fn append_subsystem_row(
    rows: &mut Vec<ActivityDagPaneRow>,
    session: &ActivitySession,
    route: &ActivityRouteState,
    width: usize,
) {
    if let Some(text) = dag_subsystems_row_text(session, route, width) {
        rows.push(ActivityDagPaneRow {
            text,
            tone: subsystem_row_tone(session.subsystem_aggregate.state),
        });
    }
}

fn append_task_legend_row(
    rows: &mut Vec<ActivityDagPaneRow>,
    session: &ActivitySession,
    width: usize,
) {
    if !session.tasks.is_empty() {
        rows.push(ActivityDagPaneRow {
            text: activity_legend_row(width),
            tone: ActivityDagRowTone::Muted,
        });
    }
}

fn append_taskless_live_row(
    rows: &mut Vec<ActivityDagPaneRow>,
    session: &ActivitySession,
    route: &ActivityRouteState,
    running_tool: Option<&str>,
) {
    if should_show_taskless_live_row(rows, session, route, running_tool) {
        rows.push(ActivityDagPaneRow {
            text: taskless_row(running_tool),
            tone: ActivityDagRowTone::Muted,
        });
    }
}

fn should_show_taskless_live_row(
    rows: &[ActivityDagPaneRow],
    session: &ActivitySession,
    route: &ActivityRouteState,
    running_tool: Option<&str>,
) -> bool {
    rows.is_empty() && running_tool.is_some() && !route.paused && session.events.is_empty()
}

fn ensure_activity_rows(mut rows: Vec<ActivityDagPaneRow>) -> Vec<ActivityDagPaneRow> {
    if rows.is_empty() {
        rows.push(ActivityDagPaneRow {
            text: " (no task rows yet)".to_string(),
            tone: ActivityDagRowTone::Muted,
        });
    }
    rows
}

fn taskless_row(running_tool: Option<&str>) -> String {
    running_tool
        .map(|tool| format!(" (single tool: {tool})"))
        .unwrap_or_else(|| " (no task rows yet)".to_string())
}

fn activity_legend_row(width: usize) -> String {
    // The active glyph must match what active rows actually render: the
    // braille spinner, not an idle-status symbol used elsewhere.
    fit(
        &format!(
            " legend: ✓ done · {} active · ⚠ partial · ! fail · × canceled · ⊘ skipped · · queued",
            SPINNER_FRAMES[0]
        ),
        width,
    )
}

fn dag_row_tone(state: DagTaskState) -> ActivityDagRowTone {
    match state {
        DagTaskState::Done => ActivityDagRowTone::Done,
        DagTaskState::Active => ActivityDagRowTone::Active,
        DagTaskState::Canceling => ActivityDagRowTone::Active,
        DagTaskState::Queued => ActivityDagRowTone::Queued,
        DagTaskState::Partial => ActivityDagRowTone::Warning,
        DagTaskState::Failing => ActivityDagRowTone::Failing,
        DagTaskState::Blocked => ActivityDagRowTone::Failing,
        DagTaskState::Canceled => ActivityDagRowTone::Canceled,
        DagTaskState::Skipped => ActivityDagRowTone::Muted,
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

fn dag_row_text(row: &DagTaskRow, width: usize, now: Instant, selected: bool) -> String {
    let symbol = match row.state {
        DagTaskState::Done => "✓",
        DagTaskState::Active => spinner_frame(now),
        DagTaskState::Canceling => "×",
        DagTaskState::Queued => "·",
        DagTaskState::Partial => "⚠",
        DagTaskState::Failing => "!",
        DagTaskState::Blocked => "▣",
        DagTaskState::Canceled => "×",
        DagTaskState::Skipped => "⊘",
    };
    let marker = if selected { "▌" } else { " " };
    let right_reserve: usize = 9;
    let task_pad = width.saturating_sub(right_reserve + 3).max(8);
    let task_label = fit(&task_display_label(row), task_pad);
    let elapsed = elapsed_label(row, now);
    let body = format!(
        "{marker} {symbol} {task:<task_pad$} {elapsed:>8}",
        marker = marker,
        symbol = symbol,
        task = task_label,
        task_pad = task_pad,
        elapsed = elapsed,
    );
    fit(&body, width)
}

fn task_display_label(row: &DagTaskRow) -> String {
    let raw = if kuzushi_core::run_lifecycle::RunTaskId::parse(&row.task_id).is_ok() {
        &row.module_id
    } else {
        &row.task_id
    };
    // `module:verb` registry keys render as their operator label; anything
    // else (custom step labels, run ids) stays verbatim.
    if raw.contains(':') {
        kuzushi_core::modules::tool_display_name(raw)
    } else {
        raw.clone()
    }
}

/// A task's row, plus — under a running task — a sub-line showing what it's
/// doing right now (its latest sub-step), so the operator sees the work inside.
fn task_pane_rows(
    route: &ActivityRouteState,
    row: &DagTaskRow,
    index: usize,
    width: usize,
    now: Instant,
) -> Vec<ActivityDagPaneRow> {
    // Rows inherited from an earlier run in the sequence stay visible for
    // history but render muted with an explicit tag — their states are that
    // run's outcome, not this one's (item 5c).
    let (text, tone) = if row.prior_run_ref.is_some() {
        (
            fit(
                &format!(
                    "{} · prior run",
                    dag_row_text(row, width, now, index == route.task_cursor).trim_end()
                ),
                width,
            ),
            ActivityDagRowTone::Muted,
        )
    } else {
        (
            dag_row_text(row, width, now, index == route.task_cursor),
            dag_row_tone(row.state),
        )
    };
    let mut out = vec![ActivityDagPaneRow { text, tone }];
    if should_show_task_details(route, row) {
        out.extend(task_detail_rows(row, width));
    } else if let Some(text) = dag_active_substep_text(row, width) {
        out.push(ActivityDagPaneRow {
            text,
            tone: ActivityDagRowTone::Muted,
        });
    }
    out
}

fn should_show_task_details(route: &ActivityRouteState, row: &DagTaskRow) -> bool {
    !row.details.is_empty()
        && (row.state == DagTaskState::Active
            || route.focus_task.as_deref() == Some(row.task_id.as_str()))
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

fn dag_subsystems_row_text(
    session: &ActivitySession,
    route: &ActivityRouteState,
    width: usize,
) -> Option<String> {
    let agg = &session.subsystem_aggregate;
    if agg.total_count == 0 {
        return None;
    }
    let label = fit(&agg.last_label, width.saturating_sub(43).max(8));
    let visibility = if route.verbose_subsystems {
        "expanded"
    } else {
        "hidden — V to expand"
    };
    Some(fit(
        &format!(
            " ⤳ subsystems ({total})  {state} · {visibility} · {label}",
            total = agg.total_count,
            state = subsystem_state_label(agg.state),
            visibility = visibility,
            label = label,
        ),
        width,
    ))
}

fn subsystem_row_tone(state: DagTaskState) -> ActivityDagRowTone {
    match state {
        DagTaskState::Partial => ActivityDagRowTone::Warning,
        DagTaskState::Failing => ActivityDagRowTone::Failing,
        DagTaskState::Blocked => ActivityDagRowTone::Failing,
        DagTaskState::Active => ActivityDagRowTone::Active,
        DagTaskState::Canceling => ActivityDagRowTone::Active,
        DagTaskState::Done => ActivityDagRowTone::Done,
        DagTaskState::Canceled => ActivityDagRowTone::Canceled,
        DagTaskState::Skipped => ActivityDagRowTone::Muted,
        DagTaskState::Queued => ActivityDagRowTone::Muted,
    }
}

fn subsystem_state_label(state: DagTaskState) -> &'static str {
    match state {
        DagTaskState::Partial => "partial",
        DagTaskState::Failing => "failing",
        DagTaskState::Blocked => "blocked",
        DagTaskState::Active => "active",
        DagTaskState::Canceling => "canceling",
        DagTaskState::Done => "done",
        DagTaskState::Canceled => "canceled",
        DagTaskState::Skipped => "not run",
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
    let secs = elapsed.as_secs();
    if secs >= 3_600 {
        format!("{}h{}m", secs / 3_600, (secs % 3_600) / 60)
    } else if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else if secs >= 1 {
        format!("{secs}s")
    } else {
        "<1s".to_string()
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

        let mut route = ActivityRouteState::default();
        route.verbose_subsystems = true;
        let rows = activity_dag_pane_rows(&session, &route, 40, Instant::now(), None);

        assert_eq!(rows.len(), 3);
        assert!(rows[0].text.contains("Run Semgrep scan"));
        assert_eq!(rows[0].tone, ActivityDagRowTone::Queued);
        assert!(rows[1].text.contains("subsystems (2)"));
        assert!(rows[1].text.contains("expanded"));
        assert_eq!(rows[1].tone, ActivityDagRowTone::Muted);
        assert!(rows[2].text.contains("legend:"));
    }

    #[test]
    fn typed_task_rows_render_operator_label_instead_of_internal_uuid() {
        let task_id = "018f47a6-b893-7d8b-8018-7d63adf3c972";
        let row = DagTaskRow::queued(task_id.to_string(), "context:build".to_string(), Vec::new());

        let text = dag_row_text(&row, 60, Instant::now(), false);

        assert!(text.contains("Build project context"));
        assert!(!text.contains(task_id));
    }

    #[test]
    fn never_started_skipped_tasks_stay_collapsed_until_verbose() {
        let mut session = ActivitySession::new("r-1");
        let mut row =
            DagTaskRow::queued("codeql:scan".to_string(), "codeql".to_string(), Vec::new());
        row.state = DagTaskState::Skipped;
        row.last_label = "not run in this scan".to_string();
        session.tasks.insert(row.task_id.clone(), row);

        let route = ActivityRouteState::default();
        let rows = activity_dag_pane_rows(&session, &route, 60, Instant::now(), None);
        assert!(rows.iter().any(|row| row.text.contains("1 not run")));
        assert!(!rows.iter().any(|row| row.text.contains("codeql:scan")));
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

        let route = ActivityRouteState::default();
        let rows = activity_dag_pane_rows(&session, &route, 60, Instant::now(), None);

        assert!(rows[0].text.contains("subsystems (1)"));
        assert!(rows[0].text.contains("failing"));
        assert_eq!(rows[0].tone, ActivityDagRowTone::Failing);
    }

    #[test]
    fn partial_task_uses_warning_copy_and_tone() {
        let mut session = ActivitySession::new("r-1");
        session.mark_task_partial("threat-model:build", "no concrete topology");

        let rows = activity_dag_pane_rows(
            &session,
            &ActivityRouteState::default(),
            80,
            Instant::now(),
            None,
        );

        assert!(rows[0].text.contains("⚠"));
        assert_eq!(rows[0].tone, ActivityDagRowTone::Warning);
        assert!(rows.last().unwrap().text.contains("⚠ partial"));
    }

    #[test]
    fn activity_dag_pane_rows_supplies_empty_state() {
        let session = ActivitySession::new("r-1");

        let route = ActivityRouteState::default();
        let rows = activity_dag_pane_rows(&session, &route, 40, Instant::now(), None);

        assert_eq!(rows.len(), 1);
        assert!(rows[0].text.contains("no task rows yet"));
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

        let route = ActivityRouteState::default();
        let rows = activity_dag_pane_rows(&session, &route, 80, Instant::now(), None);

        assert_eq!(rows.len(), 4);
        assert!(rows[0].text.contains("Agentic SAST hunt"));
        assert!(rows[1].text.contains("✓ inventory-review"));
        assert_eq!(rows[1].tone, ActivityDagRowTone::Muted);
        assert!(rows[2].text.contains("↳ vulnerability-hunt"));
        assert!(rows[2].text.contains("2.4s"));
        assert_eq!(rows[2].tone, ActivityDagRowTone::Active);
        assert!(rows[3].text.contains("legend:"));
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
    fn activity_dag_pane_rows_never_duplicates_output_events() {
        let mut session = ActivitySession::new("r-1");
        for index in 0..12 {
            session.apply_step(
                RunTraceStep::new(index + 1, "reasoning", format!("event {index}"))
                    .with_module_id("triage")
                    .with_verb("run")
                    .with_started_at_ms(42_000 + index as u64),
            );
        }

        let route = ActivityRouteState::default();
        let rows = activity_dag_pane_rows(&session, &route, 80, Instant::now(), None);

        assert_eq!(rows.len(), 1);
        assert!(rows[0].text.contains("no task rows yet"));
        assert!(rows.iter().all(|row| !row.text.contains("event")));
    }
}
