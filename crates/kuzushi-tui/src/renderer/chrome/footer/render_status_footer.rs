use super::*;

pub(crate) fn render_status_footer(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }

    let left = if app.scan.as_ref().is_some_and(|scan| scan.running) {
        join_segments(&[
            routing_mode_segment(app),
            app.config
                .model
                .clone()
                .unwrap_or_else(|| "unconfigured".to_string()),
            app.scan
                .as_ref()
                .map(scan_status)
                .unwrap_or_else(|| "idle".to_string()),
        ])
    } else if let Some(tool_name) = app.running_tool_name() {
        join_segments(&[
            routing_mode_segment(app),
            app.config
                .model
                .clone()
                .unwrap_or_else(|| "unconfigured".to_string()),
            if app.tool_abort_requested() {
                format!("{tool_name}: abort requested")
            } else {
                format!("{tool_name}: active")
            },
        ])
    } else if app.agent_chat.as_ref().is_some_and(|agent| agent.running) {
        join_segments(&[
            routing_mode_segment(app),
            app.config
                .model
                .clone()
                .unwrap_or_else(|| "unconfigured".to_string()),
            if app
                .agent_chat
                .as_ref()
                .is_some_and(|agent| agent.abort_requested)
            {
                "agent: abort requested".to_string()
            } else {
                "agent: active".to_string()
            },
        ])
    } else if app.planner_running {
        join_segments(&[
            routing_mode_segment(app),
            app.config
                .model
                .clone()
                .unwrap_or_else(|| "unconfigured".to_string()),
            if app.plan_abort_requested {
                "plan: abort requested".to_string()
            } else {
                "plan: active".to_string()
            },
        ])
    } else if app.threat_worker_running {
        join_segments(&[
            routing_mode_segment(app),
            app.config
                .model
                .clone()
                .unwrap_or_else(|| "unconfigured".to_string()),
            if app.threat_abort_requested {
                "threats: abort requested".to_string()
            } else {
                "threats: active".to_string()
            },
        ])
    } else {
        join_segments(&[
            routing_mode_segment(app),
            app.target
                .as_ref()
                .map(|path| compact_target_path(&path.display().to_string()))
                .unwrap_or_else(|| "target:none".to_string()),
            if app.context_view.exists {
                "ctx: present".to_string()
            } else {
                "ctx: missing".to_string()
            },
            view_status_segment(app),
        ])
    };

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
