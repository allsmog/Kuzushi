use super::*;
use crate::ui_view_models::routing_mode_segment;

pub(crate) fn render_status_footer(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }

    let left = status_footer_left(app);

    let mut right_segments = vec![findings_summary(&app.findings)];
    if app.ctrl_c_armed() {
        right_segments.insert(0, "Ctrl+C again to exit".to_string());
    }
    let right = join_segments(&right_segments);
    // Prefer the right segment when widths are tight: the top status strip
    // already shows mode + target + ctx, so on narrow terminals truncating
    // the duplicated left side keeps findings count + ctrl-c hint visible.
    let text = justify_prefer_right(left, right, area.width as usize);
    let style = if app.ctrl_c_armed() {
        theme::warn()
    } else {
        theme::primary()
    };
    frame.render_widget(Paragraph::new(Line::styled(text, style)), area);
}

fn status_footer_left(app: &ShellApp) -> String {
    match status_footer_activity(app) {
        Some(activity) => active_status_footer_left(app, activity),
        None => idle_status_footer_left(app),
    }
}

fn active_status_footer_left(app: &ShellApp, activity: FooterActivity) -> String {
    join_segments(&[
        routing_mode_segment(app),
        model_footer_segment(app),
        activity.label,
    ])
}

fn idle_status_footer_left(app: &ShellApp) -> String {
    join_segments(&[
        routing_mode_segment(app),
        target_footer_segment(app),
        context_footer_segment(app),
        view_status_segment(app),
    ])
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
    app.target
        .as_ref()
        .map(|path| compact_target_path(&path.display().to_string()))
        .unwrap_or_else(|| "target:none".to_string())
}

fn context_footer_segment(app: &ShellApp) -> String {
    if app.context_view.exists {
        "ctx: present".to_string()
    } else {
        "ctx: missing".to_string()
    }
}
