use super::*;
use crate::app::{PlanningArtifactState, PlanningTaskRow};

pub(crate) fn planning_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(divider("PLAN THE WORKSPACE", area.width));
    lines.push(blank());
    lines.push(muted(
        "Select foundational tasks. Dependencies auto-toggle. Steps run in order.",
    ));
    lines.push(blank());
    if app.planning_tasks.is_empty() {
        lines.push(muted("(no planning tasks available)"));
        return lines;
    }
    for (idx, row) in app.planning_tasks.iter().enumerate() {
        lines.push(planning_row_line(app, idx, row, area.width));
    }
    lines.push(blank());
    lines.push(keybind_hint_line(&[
        ("↑/↓", "move"),
        ("Space", "toggle"),
        ("a", "all"),
        ("n", "none"),
        ("Enter", "run selected"),
        ("Esc", "skip"),
    ]));
    lines
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
    let body = format!(
        "  {marker} {toggle} {label:<32} {tool:<26} {state:<8} {cost}",
        label = row.label,
        tool = row.tool_name,
        state = row.artifact_state.label(),
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
