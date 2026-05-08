use super::catalog_and_finding::{catalog_keybindings, finding_keybindings};
use super::defaults::default_keybindings;
use super::system::system_keybindings;
use super::workflow::workflow_keybindings;
use super::workspace::workspace_keybindings;
use super::*;

pub(crate) fn keybindings(app: &ShellApp) -> Vec<(&'static str, &'static str)> {
    if let Some(bindings) = active_work_keybindings(app) {
        return bindings;
    }

    let mut bindings = idle_view_keybindings(app);
    bindings.insert(0, ("Tab", "complete"));
    bindings
}

fn active_work_keybindings(app: &ShellApp) -> Option<Vec<(&'static str, &'static str)>> {
    if app.scan.as_ref().is_some_and(|scan| scan.running) {
        let mut bindings = vec![(
            "Ctrl+C",
            if app.scan.as_ref().is_some_and(|scan| scan.abort_requested) {
                "arm exit"
            } else {
                "request abort"
            },
        )];
        push_view_keybindings(&mut bindings, app);
        bindings.extend([("findings", "list"), ("back", "home")]);
        return Some(bindings);
    }
    if app.agent_chat.as_ref().is_some_and(|agent| agent.running)
        || app.planner_running
        || app.threat_worker_running
    {
        let abort_requested = app
            .agent_chat
            .as_ref()
            .is_some_and(|agent| agent.abort_requested)
            || app.plan_abort_requested
            || app.threat_abort_requested;
        return Some(vec![
            (
                "Ctrl+C",
                if abort_requested {
                    "arm exit"
                } else {
                    "request abort"
                },
            ),
            ("back", "home"),
            ("history", "events"),
            ("model", "runtime"),
        ]);
    }
    if app.running_tool_name().is_some() {
        return Some(vec![
            (
                "Ctrl+C",
                if app.tool_abort_requested() {
                    "arm exit"
                } else {
                    "request abort"
                },
            ),
            ("findings", "list"),
            ("back", "home"),
            ("history", "events"),
        ]);
    }
    None
}

fn idle_view_keybindings(app: &ShellApp) -> Vec<(&'static str, &'static str)> {
    catalog_keybindings(app)
        .or_else(|| finding_keybindings(app))
        .or_else(|| workflow_keybindings(app))
        .or_else(|| workspace_keybindings(app))
        .or_else(|| system_keybindings(app))
        .unwrap_or_else(default_keybindings)
}
