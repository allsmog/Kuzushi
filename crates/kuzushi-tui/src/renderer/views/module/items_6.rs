use super::prelude::*;
use super::*;

pub(in crate::renderer::views) fn append_progress_section(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    area: Rect,
    summary: &ModuleRunSummary,
) {
    let sast_rows = app.sast_task_rows();
    let show_per_task = sast_rows.iter().any(|row| row.selected)
        && app.focused_module.as_deref() == Some("sast")
        && (summary.scan_running || summary.scan_done);

    if append_real_scan_progress(lines, app, area, summary, show_per_task) {
        return;
    }
    if append_selected_sast_progress(lines, area, summary, &sast_rows, show_per_task) {
        return;
    }
    if app.focused_module.as_deref() == Some("sast") || summary.has_scan {
        append_sast_pipeline_progress(lines, area, summary);
        return;
    }
    if app.focused_module.as_deref() == Some("context") {
        append_context_build_progress(lines, app, area, summary);
        return;
    }
    append_generic_tool_progress(lines, app, area, summary);
}

pub(in crate::renderer::views) fn append_real_scan_progress(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    area: Rect,
    summary: &ModuleRunSummary,
    show_per_task: bool,
) -> bool {
    if !show_per_task || app.scan_progress.is_none() {
        return false;
    }

    lines.push(divider("SCAN PROGRESS", area.width));
    let progress = app.scan_progress.as_ref().expect("checked above");
    for (task_id, (done, total)) in progress.per_task.iter() {
        let (kind, status) = scan_task_progress_state(*done, *total);
        lines.push(progress_bar_line(task_id, *done, *total, status, kind));
    }
    append_triage_progress(lines, summary.findings);
    true
}

pub(in crate::renderer::views) fn scan_task_progress_state(
    done: usize,
    total: usize,
) -> (ProgressKind, &'static str) {
    if total == 0 {
        (ProgressKind::Queued, "queued")
    } else if done >= total {
        (ProgressKind::Done, "done")
    } else {
        (ProgressKind::Active, "running…")
    }
}

pub(in crate::renderer::views) fn append_selected_sast_progress(
    lines: &mut Vec<Line<'static>>,
    area: Rect,
    summary: &ModuleRunSummary,
    sast_rows: &[SastTaskRow],
    show_per_task: bool,
) -> bool {
    if !show_per_task {
        return false;
    }

    lines.push(divider("SCAN PROGRESS", area.width));
    for row in sast_rows.iter().filter(|row| row.selected) {
        let (kind, done_count, total, status) = selected_sast_task_progress(summary.scan_done);
        lines.push(progress_bar_line(row.id, done_count, total, status, kind));
    }
    append_triage_progress(lines, summary.findings);
    true
}

pub(in crate::renderer::views) fn selected_sast_task_progress(
    scan_done: bool,
) -> (ProgressKind, usize, usize, &'static str) {
    if scan_done {
        (ProgressKind::Done, 1, 1, "done")
    } else {
        (ProgressKind::Active, 0, 1, "running…")
    }
}

pub(in crate::renderer::views) fn append_triage_progress(
    lines: &mut Vec<Line<'static>>,
    findings: usize,
) {
    let status = if findings > 0 {
        "queued after scan"
    } else {
        "waiting for findings"
    };
    let kind = if findings > 0 {
        ProgressKind::Active
    } else {
        ProgressKind::Queued
    };
    lines.push(progress_bar_line(
        "triage",
        0,
        findings.max(1),
        status,
        kind,
    ));
}
