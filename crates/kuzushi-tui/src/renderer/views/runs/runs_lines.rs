use super::*;
use crate::ui_view_models::{
    run_timeline_model, ui_runs_root_relative_path, PastRunStatus, RunTimelineRow,
};

pub(crate) fn runs_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("RUN TIMELINE", area.width));
    let widths = [14usize, 12, 9, 13, value_width(area, 34)];
    lines.push(aligned_header(
        &["runId", "status", "findings", "revision", "target"],
        &widths,
    ));

    let model = run_timeline_model(app, past_run_limit(area));
    append_run_timeline_rows(&mut lines, &model.rows, &widths);
    let emitted = model.rows.len();
    append_runs_footer(&mut lines, emitted, area);
    lines
}

fn append_run_timeline_rows(
    lines: &mut Vec<Line<'static>>,
    rows: &[RunTimelineRow],
    widths: &[usize; 5],
) {
    for row in rows {
        let [run_id, status, findings, revision, target] = &row.cells;
        lines.push(runs_row(
            run_id,
            status,
            run_timeline_status_style(row.tone),
            findings,
            revision,
            target,
            widths,
        ));
    }
}

fn past_run_limit(area: Rect) -> usize {
    (area.height.saturating_sub(8) as usize).max(5).min(20)
}

fn append_runs_footer(lines: &mut Vec<Line<'static>>, emitted: usize, area: Rect) {
    if emitted == 0 {
        append_empty_runs(lines);
        return;
    }
    lines.push(blank());
    lines.push(command_list_line(
        &[
            "runs diff <left> <right>",
            "replay <runId>",
            "trace <runId>",
            "findings",
            "back",
        ],
        area.width as usize,
    ));
}

fn append_empty_runs(lines: &mut Vec<Line<'static>>) {
    let runs_root = ui_runs_root_relative_path();
    let dispatch_detail = format!("every dispatch writes a run dir under {runs_root}/<id>.");
    let first_run_detail = format!("first run will land at {runs_root}/<id>");
    lines.extend(empty_state_panel(
        "no run timeline entries",
        &[&dispatch_detail, "this workspace has not run a module yet."],
        &[
            ("scan", first_run_detail.as_str()),
            ("use context", "cheapest first run · indexes the workspace"),
        ],
    ));
}

fn run_timeline_status_style(status: PastRunStatus) -> Style {
    match status {
        PastRunStatus::Complete => theme::success(),
        PastRunStatus::Running => theme::warn(),
        PastRunStatus::Partial | PastRunStatus::Paused => theme::warn(),
        PastRunStatus::Failed | PastRunStatus::Malformed => theme::danger(),
        PastRunStatus::Unknown => theme::muted(),
    }
}
