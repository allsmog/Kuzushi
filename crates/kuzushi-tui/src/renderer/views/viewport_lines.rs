use super::*;

pub(crate) fn viewport_lines(
    lines: Vec<Line<'static>>,
    visible_height: u16,
    scroll: usize,
) -> Vec<Line<'static>> {
    let visible = visible_height as usize;
    if visible == 0 {
        return Vec::new();
    }
    if lines.len() <= visible {
        return lines;
    }
    let start = scroll.min(lines.len().saturating_sub(visible));
    lines.into_iter().skip(start).take(visible).collect()
}

pub(crate) fn viewport_start_for_cursor(
    total_rows: usize,
    visible_rows: usize,
    cursor: usize,
) -> usize {
    if total_rows <= visible_rows || visible_rows == 0 {
        return 0;
    }
    let max_start = total_rows.saturating_sub(visible_rows);
    let margin = visible_rows.saturating_sub(1) / 2;
    cursor.saturating_sub(margin).min(max_start)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoutingMode {
    Shell,
    Module,
    Agent,
    Plan,
    Run,
}

pub(crate) fn routing_mode(app: &ShellApp) -> RoutingMode {
    if app.scan.as_ref().is_some_and(|scan| scan.running)
        || app.running_tool_name().is_some()
        || matches!(app.shell_view, ShellView::ModuleRun)
    {
        RoutingMode::Run
    } else if matches!(app.shell_view, ShellView::AgentChat)
        || app.agent_chat.as_ref().is_some_and(|agent| agent.running)
    {
        RoutingMode::Agent
    } else if app.planner_running || app.pending_plan.is_some() {
        RoutingMode::Plan
    } else if app.focused_module.is_some() {
        RoutingMode::Module
    } else {
        RoutingMode::Shell
    }
}

pub(crate) fn routing_mode_segment(app: &ShellApp) -> String {
    match routing_mode(app) {
        RoutingMode::Shell => "mode:shell",
        RoutingMode::Module => "mode:module",
        RoutingMode::Agent => "mode:agent",
        RoutingMode::Plan => "mode:plan",
        RoutingMode::Run => "mode:run",
    }
    .to_string()
}
