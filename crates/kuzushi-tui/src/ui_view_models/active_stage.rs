use super::ShellApp;

pub(crate) fn active_stage_label(app: &ShellApp) -> Option<&'static str> {
    live_activity_stage(app)
        .or_else(|| scan_stage(app))
        .or_else(|| agent_chat_stage(app))
        .or_else(|| running_or_aborting(app.planner_running, app.plan_abort_requested, "thinking"))
        .or_else(|| {
            running_or_aborting(
                app.threat_worker_running,
                app.threat_abort_requested,
                "thinking",
            )
        })
}

fn live_activity_stage(app: &ShellApp) -> Option<&'static str> {
    app.live_activity
        .as_ref()
        .filter(|activity| activity.phase.active())
        .map(|activity| activity.phase.label())
}

fn scan_stage(app: &ShellApp) -> Option<&'static str> {
    app.scan
        .as_ref()
        .and_then(|scan| running_or_aborting(scan.running, scan.abort_requested, "searching"))
}

fn agent_chat_stage(app: &ShellApp) -> Option<&'static str> {
    app.agent_chat
        .as_ref()
        .and_then(|agent| running_or_aborting(agent.running, agent.abort_requested, "thinking"))
}

fn running_or_aborting(
    running: bool,
    abort_requested: bool,
    active_label: &'static str,
) -> Option<&'static str> {
    if !running {
        return None;
    }
    Some(if abort_requested {
        "aborting"
    } else {
        active_label
    })
}

#[cfg(test)]
mod tests;
