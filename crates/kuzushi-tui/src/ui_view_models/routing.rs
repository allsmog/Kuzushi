use crate::{ShellApp, ShellView};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoutingMode {
    Shell,
    Module,
    Agent,
    Plan,
    Run,
}

pub(crate) fn routing_mode(app: &ShellApp) -> RoutingMode {
    match routing_state(app) {
        (true, _, _, _) => RoutingMode::Run,
        (_, true, _, _) => RoutingMode::Agent,
        (_, _, true, _) => RoutingMode::Plan,
        (_, _, _, true) => RoutingMode::Module,
        _ => RoutingMode::Shell,
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

fn routing_state(app: &ShellApp) -> (bool, bool, bool, bool) {
    (
        has_run_activity(app),
        has_agent_activity(app),
        has_plan_activity(app),
        app.focused_module.is_some(),
    )
}

fn has_run_activity(app: &ShellApp) -> bool {
    app.scan.as_ref().is_some_and(|scan| scan.running)
        || app.running_tool_name().is_some()
        || matches!(app.shell_view, ShellView::ModuleRun)
}

fn has_agent_activity(app: &ShellApp) -> bool {
    matches!(app.shell_view, ShellView::AgentChat)
        || app.agent_chat.as_ref().is_some_and(|agent| agent.running)
}

fn has_plan_activity(app: &ShellApp) -> bool {
    app.planner_running || app.pending_plan.is_some()
}

#[cfg(test)]
mod tests;
