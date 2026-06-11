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

fn idle_status_footer_segments(app: &ShellApp) -> Vec<String> {
    let mut segments = vec![
        routing_mode_segment(app),
        target_footer_segment(app),
    ];
    if let Some(chip) = scope_footer_segment(app) {
        segments.push(chip);
    }
    segments.push(context_footer_segment(app));
    segments.push(view_status_segment(app));
    segments
}

fn scope_footer_segment(app: &ShellApp) -> Option<String> {
    let scope = app.program_scope.as_ref()?;
    if scope.is_empty() {
        return None;
    }
    Some("scope: on".to_string())
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

fn target_footer_segment(app: &ShellApp) -> String {
    let Some(path) = app.target.as_ref() else {
        return "target:none".to_string();
    };
    if target_is_cwd(path) {
        return "target:cwd (.)".to_string();
    }
    format!("target:{}", compact_target_path(&path.display().to_string()))
}

fn target_is_cwd(path: &std::path::Path) -> bool {
    let Ok(cwd) = std::env::current_dir() else {
        return false;
    };
    let Ok(cwd_canonical) = std::fs::canonicalize(&cwd) else {
        return false;
    };
    let Ok(target_canonical) = std::fs::canonicalize(path) else {
        return false;
    };
    cwd_canonical == target_canonical
}

fn context_footer_segment(app: &ShellApp) -> String {
    // Word the empty state as an action, not an alarm — the context snapshot is
    // optional and `context build` creates it (see context_strip).
    match context_snapshot_state(app) {
        "present" => "ctx:✓ built",
        "malformed" => "ctx:malformed",
        _ => "ctx:not built",
    }
    .to_string()
}

#[cfg(test)]
mod tests;
