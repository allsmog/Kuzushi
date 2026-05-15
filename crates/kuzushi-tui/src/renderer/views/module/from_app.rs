use super::*;

pub(crate) fn module_run_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let summary = module_run_summary(app);
    let findings = crate::ui_view_models::findings_model(app);

    append_run_status(&mut lines, &summary);
    append_live_activity(&mut lines, module_run_live_activity(app).as_ref(), area);
    append_progress_section(&mut lines, app, area, &summary);
    append_scan_error(&mut lines, area, &summary);
    append_findings_preview(&mut lines, &findings, area);

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

fn append_live_activity(
    lines: &mut Vec<Line<'static>>,
    activity: Option<&ModuleRunLiveActivity>,
    area: Rect,
) {
    let Some(activity) = activity else {
        return;
    };
    lines.push(divider("LIVE ACTIVITY", area.width));
    lines.push(Line::from(vec![
        Span::raw("   "),
        Span::styled(pad(activity.phase_label, 18), theme::warn()),
        Span::styled(pad(&activity.subject, 24), theme::label()),
        Span::styled(activity.detail.clone(), theme::muted()),
    ]));
}

pub(in crate::renderer::views) fn append_run_status(
    lines: &mut Vec<Line<'static>>,
    summary: &ModuleRunSummary,
) {
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::styled(
            run_state_glyph(summary.status, summary.spinner_phase),
            run_state_style(summary.status),
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
