use super::*;

pub(in crate::renderer::views) fn append_sast_pipeline_progress(
    lines: &mut Vec<Line<'static>>,
    area: Rect,
    summary: &ModuleRunSummary,
) {
    lines.push(divider("SCAN PROGRESS", area.width));
    lines.push(pipeline_row(
        if summary.active_stage.contains("context") {
            "⏵"
        } else {
            "✓"
        },
        "context:build",
        if summary.active_stage.contains("context") {
            "active"
        } else {
            "ready"
        },
    ));
    lines.push(pipeline_row(
        sast_scan_symbol(summary),
        "sast:scan",
        &summary.active_stage,
    ));
    lines.push(pipeline_row(
        "○",
        "triage:run",
        if summary.findings > 0 {
            "queued after scan"
        } else {
            "waiting for findings"
        },
    ));
}

pub(in crate::renderer::views) fn sast_scan_symbol(summary: &ModuleRunSummary) -> &'static str {
    if summary.scan_running {
        "⏵"
    } else if summary.has_scan {
        "✓"
    } else {
        "○"
    }
}

pub(in crate::renderer::views) fn append_context_build_progress(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    area: Rect,
    summary: &ModuleRunSummary,
) {
    lines.push(divider("CONTEXT BUILD", area.width));
    if let Some(tool_name) = summary.running_tool.as_deref() {
        lines.push(pipeline_row(
            "⏵",
            tool_name,
            "indexing repository context; result will update this view",
        ));
    } else if app.context_view.exists {
        lines.push(pipeline_row("✓", "context:build", &app.context_view.status));
        if let Some(path) = app.context_view.snapshot_path.as_ref() {
            lines.push(pipeline_row("◆", "snapshot", &path.display().to_string()));
        }
    } else {
        lines.push(pipeline_row(
            "○",
            "context:build",
            "no snapshot yet; `run .` builds .kuzushi/context-snapshot.json",
        ));
    }
}

pub(in crate::renderer::views) fn append_generic_tool_progress(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    area: Rect,
    summary: &ModuleRunSummary,
) {
    let module = app.focused_module.as_deref().unwrap_or("tool");
    let running = summary.tool_is_running();
    lines.push(divider("TOOL RUN", area.width));
    lines.push(pipeline_row(
        if running { "⏵" } else { "○" },
        module,
        if running {
            "running primary tool; result will update the transcript"
        } else {
            "`run .` dispatches the module's primary tool"
        },
    ));
}

pub(in crate::renderer::views) fn append_scan_error(
    lines: &mut Vec<Line<'static>>,
    area: Rect,
    summary: &ModuleRunSummary,
) {
    let Some(error) = summary.scan_error.as_ref() else {
        return;
    };

    lines.push(blank());
    let body_width = (area.width as usize).saturating_sub(6).max(20);
    let wrapped = wrap_text(error, body_width);
    for (index, segment) in wrapped.iter().enumerate() {
        lines.push(transcript_line("error", segment, index > 0));
    }
}
