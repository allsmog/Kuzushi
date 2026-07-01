use super::{bind, push_view_keybindings, FooterKeybinding};
use crate::ShellApp;

pub(super) fn active_keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    active_scan_keybindings(app)
        .or_else(|| active_agentic_keybindings(app))
        .or_else(|| active_tool_keybindings(app))
}

fn active_scan_keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    let scan = app.scan.as_ref()?;
    scan.running.then(|| {
        let mut bindings = vec![abort_binding(scan.abort_requested)];
        push_view_keybindings(&mut bindings, app);
        bindings.push(bind("findings", "list"));
        bindings
    })
}

fn active_agentic_keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    has_agentic_work(app).then(|| {
        vec![
            abort_binding(agentic_abort_requested(app)),
            bind("Esc", "back"),
            bind("history", "events"),
            bind("model", "runtime"),
        ]
    })
}

fn active_tool_keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    app.running_tool_name().map(|_| {
        vec![
            abort_binding(app.tool_abort_requested()),
            bind("findings", "list"),
            bind("Esc", "back"),
            bind("history", "events"),
        ]
    })
}

fn has_agentic_work(app: &ShellApp) -> bool {
    app.agent_chat.as_ref().is_some_and(|agent| agent.running)
        || app.planner_running
        || app.threat_worker_running
}

fn agentic_abort_requested(app: &ShellApp) -> bool {
    app.agent_chat
        .as_ref()
        .is_some_and(|agent| agent.abort_requested)
        || app.plan_abort_requested
        || app.threat_abort_requested
}

fn abort_binding(abort_requested: bool) -> FooterKeybinding {
    bind(
        "Ctrl+C",
        if abort_requested {
            "arm exit"
        } else {
            "request abort"
        },
    )
}
