use super::{
    active_project_scope_label, findings_model, journey_footer_segment, routing_mode_segment,
    scan_status, status_footer_findings_summary_from_counts,
    status_footer_findings_summary_with_total, view_status_segment, ShellApp,
};
use crate::ShellView;

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
    let mut segments = vec![routing_mode_segment(app)];
    if let Some(chip) = journey_footer_segment(app) {
        segments.push(chip);
    }
    segments.extend([
        view_status_segment(app),
        model_footer_segment(app),
        activity.label,
    ]);
    segments
}

/// Idle bottom bar: routing + current view (live orientation). Target, ctx,
/// and model live in the top cockpit strip — each session fact is stated
/// once per screen.
fn idle_status_footer_segments(app: &ShellApp) -> Vec<String> {
    // WCQ "one fact, one home": target/ctx/model live in the top cockpit
    // strip, so the bottom bar stays routing + view. The bug-bounty scope
    // chip (M2 §2.1) is kept here — it's live gating state, not a session
    // fact, so it belongs with routing/view rather than the cockpit strip.
    let mut segments = vec![routing_mode_segment(app)];
    // Engagement orientation (M-journey): the same `組 map 1/4` phase chip used
    // by the Workbench keeps the current journey step visible on every view,
    // not just inside the launch walker.
    if let Some(chip) = journey_footer_segment(app) {
        segments.push(chip);
    }
    if let Some(chip) = scope_footer_segment(app) {
        segments.push(chip);
    }
    if let Some(chip) = project_scope_footer_segment(app) {
        segments.push(chip);
    }
    segments.push(view_status_segment(app));
    segments
}

fn scope_footer_segment(app: &ShellApp) -> Option<String> {
    let scope = app.domain().program_scope()?;
    if scope.is_empty() {
        return None;
    }
    Some("scope: on".to_string())
}

fn project_scope_footer_segment(app: &ShellApp) -> Option<String> {
    active_project_scope_label(app).map(|scope| format!("project-scope:{scope}"))
}

fn status_footer_right_segments(app: &ShellApp, warning: bool) -> Vec<String> {
    let mut segments = vec![status_footer_findings_segment(app)];
    if warning {
        segments.insert(0, "Ctrl+C again to exit".to_string());
    }
    segments
}

fn status_footer_findings_segment(app: &ShellApp) -> String {
    if matches!(app.shell_view, ShellView::Workbench) {
        let findings = findings_model(app);
        return status_footer_findings_summary_from_counts(findings.total, findings.counts);
    }
    status_footer_findings_summary_with_total(app.findings(), app.findings_total_count())
}

fn status_footer_activity(app: &ShellApp) -> Option<FooterActivity> {
    // The rich chip (task · elapsed · n/m · ETA) wins whenever an activity
    // session is live; the per-worker labels below cover everything else.
    ambient_chip_activity(app)
        .or_else(|| live_footer_activity(app))
        .or_else(|| scan_footer_activity(app))
        .or_else(|| tool_footer_activity(app))
        .or_else(|| agent_footer_activity(app))
        .or_else(|| planner_footer_activity(app))
        .or_else(|| threat_footer_activity(app))
}

struct FooterActivity {
    label: String,
}

fn ambient_chip_activity(app: &ShellApp) -> Option<FooterActivity> {
    super::ambient_progress_chip(app).map(|label| FooterActivity { label })
}

fn live_footer_activity(app: &ShellApp) -> Option<FooterActivity> {
    let activity = app.live_activity()?;
    activity.phase.active().then(|| FooterActivity {
        label: activity.short_label(),
    })
}

fn scan_footer_activity(app: &ShellApp) -> Option<FooterActivity> {
    let scan = app.scan()?;
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
    let agent = app.agent_chat()?;
    agent.running.then(|| FooterActivity {
        label: active_or_abort_label("agent", agent.abort_requested),
    })
}

fn planner_footer_activity(app: &ShellApp) -> Option<FooterActivity> {
    app.planner_running().then(|| FooterActivity {
        label: active_or_abort_label("plan", app.plan_abort_requested()),
    })
}

fn threat_footer_activity(app: &ShellApp) -> Option<FooterActivity> {
    app.threat_worker_running().then(|| FooterActivity {
        label: active_or_abort_label("threats", app.threat_abort_requested()),
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
    if let Some(model) = app.active_model_override() {
        return format!("{model} (tool)");
    }
    app.config()
        .model
        .clone()
        .unwrap_or_else(|| "unconfigured".to_string())
}

#[cfg(test)]
mod tests;
