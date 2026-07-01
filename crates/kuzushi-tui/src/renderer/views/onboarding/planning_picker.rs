use super::*;
use crate::app::{
    build_execution_plan, row_disposition, PlanningArtifactState, PlanningTaskRow, RowDisposition,
    WorkflowPhase,
};

pub(crate) fn planning_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    push_phase_header(app, area.width, &mut lines);
    if app.planning_tasks.is_empty() {
        lines.push(muted("(no tasks in this phase)"));
        lines.push(blank());
        // Even with nothing to pick, the picker is still a modal — say how
        // to leave it instead of presenting a dead end.
        lines.push(keybind_hint_line(&[
            ("Enter", "continue"),
            ("Esc/q", "skip phase"),
        ]));
        return lines;
    }
    push_reuse_line(app, &mut lines);
    lines.push(blank());
    for (idx, row) in app.planning_tasks.iter().enumerate() {
        lines.push(planning_row_line(app, idx, row, area.width));
    }
    lines.push(blank());
    lines.push(muted(&enter_outcome_summary(app)));
    lines.push(keybind_hint_line(&[
        ("↑/↓/j/k", "move"),
        ("Space", "toggle"),
        ("g", "rebuild cached"),
        ("a", "all"),
        ("n", "none"),
        ("Enter", "run"),
        ("Esc/q", "skip phase"),
    ]));
    lines
}

/// State exactly what Enter will do, so a confirmed picker can never surprise:
/// `[x]` rows run, `[~]` rows are reused without running.
fn enter_outcome_summary(app: &ShellApp) -> String {
    let will_run = build_execution_plan(
        &app.planning_tasks,
        &app.planning_selected,
        &app.planning_rebuild,
    )
    .len();
    let reused = app
        .planning_tasks
        .iter()
        .filter(|row| {
            row_disposition(row, &app.planning_selected, &app.planning_rebuild)
                == RowDisposition::Reused
        })
        .count();
    match (will_run, reused) {
        (0, 0) => "Enter runs nothing (no tasks checked) — it skips to the next phase".to_string(),
        (0, reused) => format!(
            "Enter runs nothing — all {reused} checked task(s) are [~] reused; g rebuilds one"
        ),
        (will_run, 0) => format!("Enter runs {will_run} step(s)"),
        (will_run, reused) => {
            format!("Enter runs {will_run} step(s) · reuses {reused} cached without running")
        }
    }
}

/// Announce the current judo phase (組→崩→作→掛) and its intent.
fn push_phase_header(app: &ShellApp, width: u16, lines: &mut Vec<Line<'static>>) {
    match app.workflow_phase {
        Some(phase) => {
            lines.push(divider(phase.label(), width));
            lines.push(blank());
            lines.push(muted(&format!(
                "phase {} of {} — {}",
                phase.position(),
                WorkflowPhase::ORDER.len(),
                phase.intent()
            )));
        }
        None => {
            lines.push(divider("PLAN THE WORKSPACE", width));
            lines.push(blank());
            lines.push(muted(
                "Select tasks. Dependencies auto-toggle. Steps run in order.",
            ));
        }
    }
}

/// Summarize cached artifacts that will be reused (not rebuilt) this phase.
fn push_reuse_line(app: &ShellApp, lines: &mut Vec<Line<'static>>) {
    let cached: Vec<&str> = app
        .planning_tasks
        .iter()
        .filter(|row| matches!(row.artifact_state, PlanningArtifactState::Cached))
        .filter(|row| !app.planning_rebuild.contains(&row.id))
        .map(|row| row.label)
        .collect();
    if !cached.is_empty() {
        lines.push(muted(&format!(
            "reusing {} cached: {} — press g to rebuild",
            cached.len(),
            cached.join(", ")
        )));
    }
}

fn planning_row_line(
    app: &ShellApp,
    idx: usize,
    row: &PlanningTaskRow,
    width: u16,
) -> Line<'static> {
    let disposition = row_disposition(row, &app.planning_selected, &app.planning_rebuild);
    let marker = if idx == app.planning_cursor { ">" } else { " " };
    let body = format!(
        "  {marker} {toggle} {label:<32} {tool:<26} {state:<8} {cost}",
        toggle = disposition.checkbox(),
        label = row.label,
        tool = row.tool_name,
        state = planning_state_label(app, row, disposition),
        cost = planning_cost_note(app, row),
    );
    let style = planning_row_style(app, idx, row, disposition);
    Line::styled(fit(&body, width as usize), style)
}

/// The state column tracks the row's disposition: a checked cached row says
/// "reuse" (Enter will NOT run it), and `g` flips it to "rebuild".
fn planning_state_label(
    app: &ShellApp,
    row: &PlanningTaskRow,
    disposition: RowDisposition,
) -> &'static str {
    if app.planning_rebuild.contains(&row.id) {
        return "rebuild";
    }
    if disposition == RowDisposition::Reused {
        return "reuse";
    }
    row.artifact_state.label()
}

/// The row's cost column. A model-backed task with no session model can only
/// fail, so say that — and how to fix it — instead of the generic cost label.
fn planning_cost_note(app: &ShellApp, row: &PlanningTaskRow) -> String {
    if row.model_backed && app.config.model.is_none() {
        return "needs model — run /model first".to_string();
    }
    row.cost_hint()
}

fn planning_row_style(
    app: &ShellApp,
    idx: usize,
    row: &PlanningTaskRow,
    disposition: RowDisposition,
) -> Style {
    if disposition == RowDisposition::Unavailable {
        return theme::disabled();
    }
    let base = planning_row_base_style(row, disposition);
    if idx == app.planning_cursor {
        return planning_cursor_style(base, disposition);
    }
    base
}

/// Green is reserved for rows Enter will actually run; reused rows stay
/// muted so the colour can't contradict the [~] glyph.
fn planning_row_base_style(row: &PlanningTaskRow, disposition: RowDisposition) -> Style {
    match disposition {
        RowDisposition::WillRun => theme::success(),
        RowDisposition::Reused => theme::muted(),
        RowDisposition::Off if matches!(row.artifact_state, PlanningArtifactState::Cached) => {
            theme::muted()
        }
        _ => theme::primary(),
    }
}

fn planning_cursor_style(base: Style, disposition: RowDisposition) -> Style {
    if disposition == RowDisposition::WillRun {
        base.add_modifier(Modifier::BOLD)
    } else {
        theme::accent().add_modifier(Modifier::BOLD)
    }
}
