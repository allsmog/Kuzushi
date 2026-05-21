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
) {
    let context = context_snapshot_model(app);
    lines.push(divider("CONTEXT BUILD", area.width));
    if append_context_running(lines, &context) {
        return;
    }
    if append_context_snapshot(lines, &context) {
        return;
    }
    if append_context_malformed(lines, &context) {
        return;
    }
    lines.push(pipeline_row(
        "○",
        "context:build",
        "no snapshot yet; `run .` builds .kuzushi/context-snapshot.json",
    ));
}

fn append_context_running(lines: &mut Vec<Line<'static>>, context: &ContextSnapshotModel) -> bool {
    let Some(running) = context.running.as_ref() else {
        return false;
    };
    lines.push(pipeline_row(running.glyph, &running.tool, running.message));
    true
}

fn append_context_snapshot(lines: &mut Vec<Line<'static>>, context: &ContextSnapshotModel) -> bool {
    if !context.snapshot_present {
        return false;
    }
    lines.push(pipeline_row("✓", "context:build", &context.status));
    lines.push(pipeline_row("◆", "snapshot", &context.snapshot));
    true
}

fn append_context_malformed(
    lines: &mut Vec<Line<'static>>,
    context: &ContextSnapshotModel,
) -> bool {
    if context.state != "malformed" {
        return false;
    }
    lines.push(pipeline_row("⚠", "context:build", &context.status));
    lines.push(pipeline_row("◆", "snapshot", &context.snapshot));
    true
}

pub(in crate::renderer::views) fn append_generic_tool_progress(
    lines: &mut Vec<Line<'static>>,
    area: Rect,
    module: &str,
    summary: &ModuleRunSummary,
) {
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
