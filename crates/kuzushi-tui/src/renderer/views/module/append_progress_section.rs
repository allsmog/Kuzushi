use super::*;

pub(in crate::renderer::views) fn append_progress_section(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    area: Rect,
    summary: &ModuleRunSummary,
) {
    append_projected_progress(
        lines,
        app,
        area,
        summary,
        module_progress_model(app, summary),
    );
}

fn append_projected_progress(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    area: Rect,
    summary: &ModuleRunSummary,
    model: ModuleProgressModel,
) {
    match model.section {
        ModuleProgressSection::RealScan { rows } | ModuleProgressSection::SelectedSast { rows } => {
            append_progress_rows(lines, area, rows);
        }
        ModuleProgressSection::SastPipeline => append_sast_pipeline_progress(lines, area, summary),
        ModuleProgressSection::ContextBuild => append_context_build_progress(lines, app, area),
        ModuleProgressSection::GenericTool { module } => {
            append_generic_tool_progress(lines, area, &module, summary)
        }
    }
}

fn append_progress_rows(lines: &mut Vec<Line<'static>>, area: Rect, rows: Vec<ModuleProgressRow>) {
    lines.push(divider("SCAN PROGRESS", area.width));
    for row in rows {
        lines.push(progress_bar_line(
            &row.label,
            row.done,
            row.total,
            row.status,
            progress_kind(row.kind),
        ));
    }
}

fn progress_kind(kind: ModuleProgressKind) -> ProgressKind {
    match kind {
        ModuleProgressKind::Done => ProgressKind::Done,
        ModuleProgressKind::Active => ProgressKind::Active,
        ModuleProgressKind::Queued => ProgressKind::Queued,
    }
}
