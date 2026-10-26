use super::{
    active_project_scope_label, autonomy_footer_segment,
    compact_status_footer_findings_summary_from_counts,
    compact_status_footer_findings_summary_with_total, findings_model, journey_footer_segment,
    routing_mode_segment, scan_status, status_footer_findings_summary_from_counts,
    status_footer_findings_summary_with_total, view_status_segment, FindingsNarrowing, ShellApp,
};
use crate::app::{ProgramScopeState, ReviewMode};
use crate::ShellView;

mod investigation;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatusFooterModel {
    pub(crate) left_segments: Vec<String>,
    pub(crate) right_segments: Vec<String>,
    pub(crate) compact_left_segments: Vec<String>,
    pub(crate) compact_right_segments: Vec<String>,
}

pub(crate) fn status_footer_model(app: &ShellApp) -> StatusFooterModel {
    let (mut right, mut compact_right) = status_footer_findings_segments(app);
    let allowance = super::report_summary::report_allowance_calls(app).or_else(|| {
        super::investigation_allowance::investigation_allowance_model(app)
            .map(|allowance| allowance.calls)
    });
    let has_allowance = allowance.is_some();
    if let Some(allowance) = allowance {
        right = format!("{allowance} · {right}");
        compact_right = allowance;
    }
    StatusFooterModel {
        left_segments: investigation::full_segments(app)
            .unwrap_or_else(|| status_footer_left_segments(app)),
        right_segments: vec![right],
        compact_left_segments: investigation::compact_segments(app, has_allowance)
            .unwrap_or_else(|| compact_status_footer_left_segments(app, has_allowance)),
        compact_right_segments: vec![compact_right],
    }
}

/// The operator's ceiling must survive truncation of routing and diagnostics.
fn leading_footer_segments(app: &ShellApp) -> Vec<String> {
    let mut segments = Vec::new();
    segments.extend(autonomy_footer_segment(app));
    segments.extend(workspace_stale_footer_segment(app));
    segments.push(routing_mode_segment(app));
    segments
}

fn compact_status_footer_left_segments(app: &ShellApp, has_allowance: bool) -> Vec<String> {
    if let Some(state) = compact_source_attention(app) {
        let state = match (state, has_allowance) {
            ("source check", true) => "source",
            _ => state,
        };
        return compact_source_footer_segments(app, state);
    }
    let mut segments = leading_footer_segments(app);
    if let Some(attention) = attention_footer_segment(app) {
        segments.push(attention);
    }
    if let Some(notify) = compact_notification_availability_footer_segment(app) {
        segments.push(notify);
    }
    segments.push(view_status_segment(app));
    segments
}

fn compact_source_attention(app: &ShellApp) -> Option<&'static str> {
    if app.workspace_stale().is_some() {
        return Some("stale");
    }
    app.domain()
        .returning_source_unverified()
        .then_some("source check")
}

fn compact_source_footer_segments(app: &ShellApp, state: &str) -> Vec<String> {
    let mut policy = autonomy_footer_segment(app).unwrap_or_else(|| "source".to_string());
    if !policy.ends_with('⚠') {
        policy.push_str(" ⚠");
    }
    policy.push(' ');
    policy.push_str(state);
    let mut segments = vec![policy];
    segments.extend(attention_footer_segment(app));
    segments
}

fn status_footer_left_segments(app: &ShellApp) -> Vec<String> {
    match status_footer_activity(app) {
        Some(activity) => active_status_footer_segments(app, activity),
        None => idle_status_footer_segments(app),
    }
}

fn active_status_footer_segments(app: &ShellApp, activity: FooterActivity) -> Vec<String> {
    let mut segments = leading_footer_segments(app);
    segments.push(activity.label);
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
    let mut segments = leading_footer_segments(app);
    // Engagement orientation (M-journey): the same `組 map 1/5` phase chip used
    // by the Workbench keeps the current journey step visible on every view,
    // not just inside the launch walker.
    segments.extend(optional_idle_chips(app));
    segments.push(view_status_segment(app));
    segments
}

fn optional_active_chips(app: &ShellApp) -> impl Iterator<Item = String> {
    [
        attention_footer_segment(app),
        notification_availability_footer_segment(app),
        journey_footer_segment(app),
        review_conflict_footer_segment(app),
    ]
    .into_iter()
    .flatten()
}

fn optional_idle_chips(app: &ShellApp) -> impl Iterator<Item = String> {
    [
        attention_footer_segment(app),
        notification_availability_footer_segment(app),
        journey_footer_segment(app),
        scope_footer_segment(app),
        project_scope_footer_segment(app),
        review_conflict_footer_segment(app),
    ]
    .into_iter()
    .flatten()
}

fn attention_footer_segment(app: &ShellApp) -> Option<String> {
    crate::AttentionBroker::from_app(app).footer_segment()
}

fn notification_availability_footer_segment(app: &ShellApp) -> Option<String> {
    desktop_alerts_unavailable(app).then(|| "Desktop alerts unavailable".to_string())
}

fn compact_notification_availability_footer_segment(app: &ShellApp) -> Option<String> {
    desktop_alerts_unavailable(app).then(|| "No desktop alerts".to_string())
}

fn desktop_alerts_unavailable(app: &ShellApp) -> bool {
    app.ui().notify_enabled() && app.ui().terminal_focus() == crate::app::FocusState::Unknown
}

/// The program-scope chip. An unloadable `scope.toml` reads as
/// `scope: load failed` rather than as no chip at all, so the one always-visible
/// signifier of the bug-bounty boundary never presents a broken allow/deny list
/// as an absent one. An empty scope stays chipless: its lists are a no-op.
fn scope_footer_segment(app: &ShellApp) -> Option<String> {
    if matches!(
        app.domain().program_scope_state(),
        ProgramScopeState::Unavailable
    ) {
        return Some("scope: load failed".to_string());
    }
    let scope = app.domain().program_scope()?;
    (!scope.is_empty()).then(|| "scope: on".to_string())
}

fn project_scope_footer_segment(app: &ShellApp) -> Option<String> {
    active_project_scope_label(app).map(|scope| format!("project-scope:{scope}"))
}

fn workspace_stale_footer_segment(app: &ShellApp) -> Option<String> {
    if let Some(stale) = app.workspace_stale() {
        return Some(stale.chip());
    }
    app.domain()
        .returning_source_unverified()
        .then(|| "history:check source".to_string())
}

fn review_conflict_footer_segment(app: &ShellApp) -> Option<String> {
    matches!(
        &app.router.workbench().review().mode,
        ReviewMode::Conflict { .. }
    )
    .then(|| "review:conflict".to_string())
}

fn status_footer_findings_segments(app: &ShellApp) -> (String, String) {
    if matches!(app.shell_view(), ShellView::Report) {
        let summary = super::report_summary::report_review_footer_summary(app);
        return (summary.clone(), summary);
    }
    let (full, compact) = (
        status_footer_findings_segment(app),
        compact_status_footer_findings_segment(app),
    );
    if matches!(app.shell_view(), ShellView::Replay) {
        return (format!("Workspace {full}"), format!("Workspace {compact}"));
    }
    (full, compact)
}

// Workbench counts the projection the operator is actually looking at, while
// the context rail beside it counts the unfiltered ledger. Both are true, and
// both used to print as a bare `N findings`, so a narrowed Workbench put two
// contradicting totals on one frame. Carrying the ledger total into the
// segment lets the narrower number disclose what it is narrowed from.
fn status_footer_findings_segment(app: &ShellApp) -> String {
    if matches!(app.shell_view(), ShellView::Workbench) {
        let findings = findings_model(app);
        return status_footer_findings_summary_from_counts(
            workbench_findings_narrowing(app, findings.total),
            findings.counts,
        );
    }
    status_footer_findings_summary_with_total(app.findings(), app.findings_total_count())
}

fn workbench_findings_narrowing(app: &ShellApp, shown: usize) -> FindingsNarrowing {
    FindingsNarrowing {
        shown,
        loaded: app.findings().len(),
        total: app.findings_total_count(),
    }
}

fn compact_status_footer_findings_segment(app: &ShellApp) -> String {
    if matches!(app.shell_view(), ShellView::Workbench) {
        let findings = findings_model(app);
        return compact_status_footer_findings_summary_from_counts(
            workbench_findings_narrowing(app, findings.total),
            findings.counts,
        );
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
