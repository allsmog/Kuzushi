use super::*;
use crate::app::{PlanningArtifactState, PlanningTaskRow, WorkflowPhase};

pub(crate) fn planning_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    push_phase_header(app, area.width, &mut lines);
    if app.planning_tasks.is_empty() {
        lines.push(muted("(no tasks in this phase)"));
        return lines;
    }
    push_reuse_line(app, &mut lines);
    lines.push(blank());
    for (idx, row) in app.planning_tasks.iter().enumerate() {
        lines.push(planning_row_line(app, idx, row, area.width));
    }
    lines.push(blank());
    lines.push(keybind_hint_line(&[
        ("↑/↓", "move"),
        ("Space", "toggle"),
        ("g", "rebuild cached"),
        ("a", "all"),
        ("n", "none"),
        ("Enter", "run"),
        ("Esc", "skip phase"),
    ]));
    lines
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
    let checked = app.planning_selected.contains(&row.id);
    let marker = if idx == app.planning_cursor { ">" } else { " " };
    let toggle = if checked { "[x]" } else { "[ ]" };
    let state = if app.planning_rebuild.contains(&row.id) {
        "rebuild"
    } else {
        row.artifact_state.label()
    };
    let body = format!(
        "  {marker} {toggle} {label:<32} {tool:<26} {state:<8} {cost}",
        label = row.label,
        tool = row.tool_name,
        state = state,
        cost = row.cost_hint(),
    );
    let style = planning_row_style(app, idx, row, checked);
    Line::styled(fit(&body, width as usize), style)
}

fn planning_row_style(app: &ShellApp, idx: usize, row: &PlanningTaskRow, checked: bool) -> Style {
    if !row.cli_available {
        return theme::muted().add_modifier(Modifier::DIM);
    }
    if idx == app.planning_cursor {
        if checked {
            theme::success().add_modifier(Modifier::BOLD)
        } else {
            theme::accent().add_modifier(Modifier::BOLD)
        }
    } else if checked {
        theme::success()
    } else if matches!(row.artifact_state, PlanningArtifactState::Cached) {
        theme::muted()
    } else {
        theme::primary()
    }
}
