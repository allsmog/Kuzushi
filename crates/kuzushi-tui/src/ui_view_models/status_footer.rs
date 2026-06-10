use super::{
    compact_target_path, context_snapshot_state, routing_mode_segment, scan_status,
    status_footer_findings_summary, view_status_segment, ShellApp,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatusFooterModel {
    pub(crate) left_segments: Vec<String>,
    pub(crate) right_segments: Vec<String>,
    pub(crate) warning: bool,
}

pub(crate) fn status_footer_model(app: &ShellApp) -> StatusFooterModel {
    let warning = app.ctrl_c_armed();
    StatusFooterModel {
        left_segments: status_footer_left_segments(app),
        right_segments: status_footer_right_segments(app, warning),
        warning,
    }
}

fn status_footer_left_segments(app: &ShellApp) -> Vec<String> {
    match status_footer_activity(app) {
        Some(activity) => active_status_footer_segments(app, activity),
        None => idle_status_footer_segments(app),
    }
}

fn active_status_footer_segments(app: &ShellApp, activity: FooterActivity) -> Vec<String> {
    vec![
        routing_mode_segment(app),
        model_footer_segment(app),
        activity.label,
    ]
}

/// Idle bottom bar: routing + current view (live orientation). Target, ctx,
/// and model live in the top cockpit strip — each session fact is stated
/// once per screen.
fn idle_status_footer_segments(app: &ShellApp) -> Vec<String> {
    vec![routing_mode_segment(app), view_status_segment(app)]
}

fn status_footer_right_segments(app: &ShellApp, warning: bool) -> Vec<String> {
    let mut segments = vec![status_footer_findings_summary(&app.findings)];
    if warning {
        segments.insert(0, "Ctrl+C again to exit".to_string());
    }
    segments
}

fn status_footer_activity(app: &ShellApp) -> Option<FooterActivity> {
    live_footer_activity(app)
        .or_else(|| scan_footer_activity(app))
        .or_else(|| tool_footer_activity(app))
        .or_else(|| agent_footer_activity(app))
        .or_else(|| planner_footer_activity(app))
        .or_else(|| threat_footer_activity(app))
}

struct FooterActivity {
    label: String,
}

fn live_footer_activity(app: &ShellApp) -> Option<FooterActivity> {
    let activity = app.live_activity.as_ref()?;
    activity.phase.active().then(|| FooterActivity {
        label: activity.short_label(),
    })
}

fn scan_footer_activity(app: &ShellApp) -> Option<FooterActivity> {
    let scan = app.scan.as_ref()?;
    scan.running.then(|| FooterActivity {
        label: scan_status(scan),
    })
}

fn tool_footer_activity(app: &ShellApp) -> Option<FooterActivity> {
    let tool_name = app.running_tool_name()?;
    Some(FooterActivity {
        label: active_or_abort_label(tool_name, app.tool_abort_requested()),
    })
}

fn agent_footer_activity(app: &ShellApp) -> Option<FooterActivity> {
    let agent = app.agent_chat.as_ref()?;
    agent.running.then(|| FooterActivity {
        label: active_or_abort_label("agent", agent.abort_requested),
    })
}

fn planner_footer_activity(app: &ShellApp) -> Option<FooterActivity> {
    app.planner_running.then(|| FooterActivity {
        label: active_or_abort_label("plan", app.plan_abort_requested),
    })
}

fn threat_footer_activity(app: &ShellApp) -> Option<FooterActivity> {
    app.threat_worker_running.then(|| FooterActivity {
        label: active_or_abort_label("threats", app.threat_abort_requested),
    })
}

fn active_or_abort_label(name: &str, abort_requested: bool) -> String {
    if abort_requested {
        format!("{name}: abort requested")
    } else {
        format!("{name}: active")
    }
}

fn model_footer_segment(app: &ShellApp) -> String {
    app.config
        .model
        .clone()
        .unwrap_or_else(|| "unconfigured".to_string())
}

#[cfg(test)]
mod tests;
