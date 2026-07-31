use super::{
    active_project_scope_label, autonomy_footer_segment,
    compact_status_footer_findings_summary_from_counts,
    compact_status_footer_findings_summary_with_total, findings_model, journey_footer_segment,
    routing_mode_segment, scan_status, status_footer_findings_summary_from_counts,
    status_footer_findings_summary_with_total, view_status_segment, ShellApp,
};
use crate::app::ReviewMode;
use crate::ShellView;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatusFooterModel {
    pub(crate) left_segments: Vec<String>,
    pub(crate) right_segments: Vec<String>,
    pub(crate) compact_left_segments: Vec<String>,
    pub(crate) compact_right_segments: Vec<String>,
}

pub(crate) fn status_footer_model(app: &ShellApp) -> StatusFooterModel {
    StatusFooterModel {
        left_segments: status_footer_left_segments(app),
        right_segments: status_footer_right_segments(app),
        compact_left_segments: compact_status_footer_left_segments(app),
        compact_right_segments: compact_status_footer_right_segments(app),
    }
}

fn compact_status_footer_left_segments(app: &ShellApp) -> Vec<String> {
    let mut segments = vec![routing_mode_segment(app)];
    if let Some(attention) = attention_footer_segment(app) {
        segments.push(attention);
    }
    segments.push(view_status_segment(app));
    segments
}

fn status_footer_left_segments(app: &ShellApp) -> Vec<String> {
    match status_footer_activity(app) {
        Some(activity) => active_status_footer_segments(app, activity),
        None => idle_status_footer_segments(app),
    }
}

fn active_status_footer_segments(app: &ShellApp, activity: FooterActivity) -> Vec<String> {
    // Activity is ambient safety state, so keep it immediately after routing.
    // Lower-priority journey/model chips may truncate at narrow widths without
    // hiding the fact that work is still executing in the background.
    let mut segments = vec![routing_mode_segment(app), activity.label];
    segments.extend(optional_active_chips(app));
    segments.extend([view_status_segment(app), model_footer_segment(app)]);
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
    // Engagement orientation (M-journey): the same `組 map 1/5` phase chip used
    // by the Workbench keeps the current journey step visible on every view,
    // not just inside the launch walker.
    segments.extend(optional_idle_chips(app));
    segments.push(view_status_segment(app));
    segments
}

fn optional_active_chips(app: &ShellApp) -> impl Iterator<Item = String> {
    let onboarding = setup_is_in_progress(app);
    [
        attention_footer_segment(app),
        (!onboarding).then(|| journey_footer_segment(app)).flatten(),
        (!onboarding)
            .then(|| autonomy_footer_segment(app))
            .flatten(),
        review_conflict_footer_segment(app),
        workspace_stale_footer_segment(app),
    ]
    .into_iter()
    .flatten()
}

fn optional_idle_chips(app: &ShellApp) -> impl Iterator<Item = String> {
    let onboarding = setup_is_in_progress(app);
    [
        attention_footer_segment(app),
        (!onboarding).then(|| journey_footer_segment(app)).flatten(),
        // The autonomy dial rides beside the phase chip — the always-visible
        // master control (`⛭ 作 prove`, with `⚠` when it throttles the walker).
        (!onboarding)
            .then(|| autonomy_footer_segment(app))
            .flatten(),
        scope_footer_segment(app),
        project_scope_footer_segment(app),
        review_conflict_footer_segment(app),
        workspace_stale_footer_segment(app),
    ]
    .into_iter()
    .flatten()
}

fn attention_footer_segment(app: &ShellApp) -> Option<String> {
    crate::AttentionBroker::from_app(app).footer_segment()
}

fn setup_is_in_progress(app: &ShellApp) -> bool {
    matches!(app.shell_view(), ShellView::TargetPicker | ShellView::Setup)
        || app.router.setup().editor().is_some()
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

fn workspace_stale_footer_segment(app: &ShellApp) -> Option<String> {
    app.workspace_stale().map(|stale| stale.chip())
}

fn review_conflict_footer_segment(app: &ShellApp) -> Option<String> {
    matches!(
        &app.router.workbench().review().mode,
        ReviewMode::Conflict { .. }
    )
    .then(|| "review:conflict".to_string())
}

fn status_footer_right_segments(app: &ShellApp) -> Vec<String> {
    vec![status_footer_findings_segment(app)]
}

fn compact_status_footer_right_segments(app: &ShellApp) -> Vec<String> {
    vec![compact_status_footer_findings_segment(app)]
}

fn status_footer_findings_segment(app: &ShellApp) -> String {
    if matches!(app.shell_view(), ShellView::Workbench) {
        let findings = findings_model(app);
        return status_footer_findings_summary_from_counts(findings.total, findings.counts);
    }
    status_footer_findings_summary_with_total(app.findings(), app.findings_total_count())
}

fn compact_status_footer_findings_segment(app: &ShellApp) -> String {
    if matches!(app.shell_view(), ShellView::Workbench) {
        let findings = findings_model(app);
        return compact_status_footer_findings_summary_from_counts(findings.total, findings.counts);
    }
    compact_status_footer_findings_summary_with_total(app.findings(), app.findings_total_count())
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
