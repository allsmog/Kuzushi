use super::*;
use crate::ui_view_models::{
    jobs_registry_model, ui_runs_root_relative_path, JobRow, JobRunStatus,
};

const JOBS_COLUMN_WIDTHS: [usize; 6] = [16, 8, 11, 8, 20, 8];

/// The `jobs` registry: the operator control surface over live + recent runs.
/// Extends the historical Runs timeline with elapsed, current step, queued
/// steer rows, and `-k` cancel. Live rows render first; queued items are toned
/// as pending so the single-live-run reality is never misrepresented.
pub(crate) fn jobs_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("JOBS", area.width));
    let widths = column_widths(area);
    lines.push(aligned_header(
        &[
            "runId", "kind", "status", "elapsed", "step", "findings", "target",
        ],
        &widths,
    ));

    let model = jobs_registry_model(app, past_run_limit(area));
    for row in &model.rows {
        lines.push(job_row_line(row, &widths));
    }
    append_jobs_footer(&mut lines, &model, area);
    lines
}

fn column_widths(area: Rect) -> [usize; 7] {
    let [run_id, kind, status, elapsed, step, findings] = JOBS_COLUMN_WIDTHS;
    let fixed_used = run_id + kind + status + elapsed + step + findings + 14;
    [
        run_id,
        kind,
        status,
        elapsed,
        step,
        findings,
        value_width(area, fixed_used),
    ]
}

fn job_row_line(row: &JobRow, widths: &[usize; 7]) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{}  ", pad(&fit(&row.run_id, widths[0]), widths[0])),
            theme::accent(),
        ),
        Span::styled(
            format!("{}  ", pad(&fit(&row.kind, widths[1]), widths[1])),
            theme::subtle(),
        ),
        Span::styled(
            format!("{}  ", pad(row.status.label(), widths[2])),
            job_status_style(row.status),
        ),
        Span::styled(
            format!("{}  ", pad(&elapsed_label(row), widths[3])),
            theme::subtle(),
        ),
        Span::styled(
            format!("{}  ", pad(&fit(&phase_label(row), widths[4]), widths[4])),
            theme::primary(),
        ),
        Span::styled(
            format!("{}  ", pad(&findings_label(row), widths[5])),
            theme::primary(),
        ),
        Span::styled(
            format!("{}  ", pad(&fit(&row.target, widths[6]), widths[6])),
            theme::muted(),
        ),
    ])
}

fn elapsed_label(row: &JobRow) -> String {
    row.elapsed_secs
        .map(crate::app::compact_secs)
        .unwrap_or_else(|| "—".to_string())
}

fn phase_label(row: &JobRow) -> String {
    row.phase.clone().unwrap_or_else(|| "—".to_string())
}

fn findings_label(row: &JobRow) -> String {
    row.findings
        .map(|count| count.to_string())
        .unwrap_or_else(|| "—".to_string())
}

fn job_status_style(status: JobRunStatus) -> Style {
    match status {
        JobRunStatus::Running => theme::success(),
        JobRunStatus::Queued => theme::warn(),
        JobRunStatus::Completed => theme::success(),
        JobRunStatus::Partial | JobRunStatus::Interrupted => theme::warn(),
        JobRunStatus::Failed => theme::danger(),
        JobRunStatus::Skipped | JobRunStatus::Unknown => theme::muted(),
    }
}

fn past_run_limit(area: Rect) -> usize {
    (area.height.saturating_sub(8) as usize).clamp(5, 20)
}

fn append_jobs_footer(
    lines: &mut Vec<Line<'static>>,
    model: &crate::ui_view_models::JobsRegistryModel,
    area: Rect,
) {
    if model.rows.is_empty() {
        append_empty_jobs(lines);
        return;
    }
    lines.push(blank());
    if model.live_count == 0 {
        lines.push(Line::styled(
            "  no live jobs — recent runs shown; start work with `scan` or `run <tool>`",
            theme::muted(),
        ));
    }
    lines.push(command_list_line(
        &[
            "jobs -k <id>",
            "trace <id>",
            "replay <id>",
            "background",
            "runs",
            "back",
        ],
        area.width as usize,
    ));
}

fn append_empty_jobs(lines: &mut Vec<Line<'static>>) {
    let runs_root = ui_runs_root_relative_path();
    let detail = format!("live jobs appear here while running; recent runs load from {runs_root}/<id>.");
    lines.extend(empty_state_panel(
        "no jobs yet",
        &[&detail, "this workspace has not run a module yet."],
        &[
            ("scan", "start a background scan · streams into this registry"),
            ("run <tool>", "queue more with `queue <tool>` while one runs"),
        ],
    ));
}
