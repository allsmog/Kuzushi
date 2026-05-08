use super::*;

impl ModuleRunSummary {
    pub(in crate::renderer::views) fn from_app(app: &ShellApp) -> Self {
        let scan = app.scan.as_ref();
        let running_tool = app.running_tool_name().map(str::to_string);
        let target = scan
            .map(|scan| compact_target_path(&scan.target.display().to_string()))
            .or_else(|| {
                app.target
                    .as_ref()
                    .map(|path| compact_target_path(&path.display().to_string()))
            })
            .unwrap_or_else(|| "target:none".to_string());
        let stage = scan
            .map(scan_status)
            .or_else(|| {
                app.live_activity
                    .as_ref()
                    .map(|activity| activity.phase.label().to_string())
            })
            .or_else(|| running_tool.as_ref().map(|_| "running tool".to_string()))
            .unwrap_or_else(|| "idle".to_string());
        let findings = scan
            .map(|scan| scan.findings_count)
            .unwrap_or(app.findings.len());
        let run = scan
            .and_then(|scan| scan.run_id.as_ref())
            .map(|run_id| format!("run {}", short(run_id)))
            .unwrap_or_else(|| run_label_without_id(scan.is_some(), running_tool.as_deref()));
        let active_stage = scan
            .map(|scan| scan.stage.clone())
            .unwrap_or_else(|| "idle".to_string());
        let scan_running = scan.is_some_and(|scan| scan.running);
        let scan_done =
            scan.is_some() && !scan_running && scan.and_then(|scan| scan.error.as_ref()).is_none();
        let scan_error = scan.and_then(|scan| scan.error.clone());

        Self {
            target,
            stage,
            findings,
            run,
            active_stage,
            scan_running,
            scan_done,
            has_scan: scan.is_some(),
            running_tool,
            scan_error,
        }
    }

    pub(in crate::renderer::views) fn tool_is_running(&self) -> bool {
        self.running_tool.is_some()
    }
}

pub(in crate::renderer::views) fn run_label_without_id(
    has_scan: bool,
    running_tool: Option<&str>,
) -> String {
    if has_scan {
        "run pending".to_string()
    } else if let Some(tool_name) = running_tool {
        tool_name.to_string()
    } else {
        "tool run".to_string()
    }
}

pub(crate) fn module_run_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let summary = ModuleRunSummary::from_app(app);

    append_run_status(
        &mut lines,
        app.scan.as_ref(),
        &summary,
        app.spinner_phase as usize,
    );
    append_live_activity(&mut lines, app, area);
    append_progress_section(&mut lines, app, area, &summary);
    append_scan_error(&mut lines, area, &summary);
    append_findings_preview(&mut lines, app, area);

    lines.push(blank());
    lines.push(divider("TRANSCRIPT", area.width));
    let body_budget = area.height.saturating_sub(lines.len() as u16) as usize;
    let transcript = transcript_lines(app, body_budget.saturating_sub(1).max(0));
    lines.extend(transcript);
    if (summary.scan_running || summary.tool_is_running()) && body_budget > 0 {
        lines.push(streaming_cursor_line());
    }
    lines
}

fn append_live_activity(lines: &mut Vec<Line<'static>>, app: &ShellApp, area: Rect) {
    let Some(activity) = app.live_activity.as_ref() else {
        return;
    };
    lines.push(divider("LIVE ACTIVITY", area.width));
    lines.push(Line::from(vec![
        Span::raw("   "),
        Span::styled(pad(activity.phase.label(), 18), theme::warn()),
        Span::styled(pad(&activity.subject, 24), theme::label()),
        Span::styled(activity.detail.clone(), theme::muted()),
    ]));
}

pub(in crate::renderer::views) fn append_run_status(
    lines: &mut Vec<Line<'static>>,
    scan: Option<&ScanPanelState>,
    summary: &ModuleRunSummary,
    spinner_phase: usize,
) {
    let tool_running = summary.tool_is_running();
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::styled(
            run_state_glyph(scan, tool_running, spinner_phase),
            run_state_style(scan, tool_running),
        ),
        Span::raw(" "),
        Span::styled(summary.target.clone(), theme::label()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::raw(summary.stage.clone()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(format!("{} finding(s)", summary.findings), theme::muted()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(summary.run.clone(), theme::muted()),
    ]));
    lines.push(blank());
}
