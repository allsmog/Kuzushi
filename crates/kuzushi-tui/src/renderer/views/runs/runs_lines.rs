use super::*;
use crate::ui_view_models::{past_runs_model, PastRunStatus};

pub(crate) fn runs_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("RUN TIMELINE", area.width));
    let widths = [12usize, 14, 9, value_width(area, 40)];
    lines.push(aligned_header(
        &["runId", "status", "findings", "target"],
        &widths,
    ));

    let emitted = append_active_scan_row(&mut lines, app, &widths)
        + append_past_run_rows(&mut lines, app, area, &widths);
    append_runs_footer(&mut lines, emitted, area);
    lines
}

fn append_active_scan_row(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    widths: &[usize; 4],
) -> usize {
    let Some(scan) = &app.scan else { return 0 };
    let run_id = scan
        .run_id
        .as_deref()
        .map(short)
        .unwrap_or_else(|| "pending".to_string());
    lines.push(runs_row(
        &run_id,
        &scan_status(scan),
        active_scan_style(scan),
        &scan.findings_count.to_string(),
        &scan.target.display().to_string(),
        widths,
    ));
    1
}

fn append_past_run_rows(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    area: Rect,
    widths: &[usize; 4],
) -> usize {
    let mut past_runs = past_runs_model(app);
    past_runs.sort_by(|a, b| b.run_id.cmp(&a.run_id));
    let take = (area.height.saturating_sub(8) as usize).max(5).min(20);
    let mut emitted = 0;
    for past in past_runs.iter().take(take) {
        if active_scan_matches(app, &past.run_id) {
            continue;
        }
        lines.push(runs_row(
            &short(&past.run_id),
            past.status_label(),
            past_run_style(past.status_kind),
            &finding_count_label(past.findings),
            &past.target,
            widths,
        ));
        emitted += 1;
    }
    emitted
}

fn append_runs_footer(lines: &mut Vec<Line<'static>>, emitted: usize, area: Rect) {
    if emitted == 0 {
        append_empty_runs(lines);
        return;
    }
    lines.push(blank());
    lines.push(command_list_line(
        &["replay <runId>", "trace <runId>", "findings", "back"],
        area.width as usize,
    ));
}

fn append_empty_runs(lines: &mut Vec<Line<'static>>) {
    lines.extend(empty_state_panel(
        "no run timeline entries",
        &[
            "every dispatch writes a run dir under .kuzushi/runs/<id>/.",
            "this workspace has not run a module yet.",
        ],
        &[
            ("scan", "first run will land at .kuzushi/runs/<id>/"),
            ("use context", "cheapest first run · indexes the workspace"),
        ],
    ));
}

fn active_scan_style(scan: &ScanPanelState) -> Style {
    if scan.error.is_some() {
        return theme::danger();
    }
    if scan.running {
        theme::warn()
    } else {
        theme::success()
    }
}

fn active_scan_matches(app: &ShellApp, run_id: &str) -> bool {
    let Some(scan) = &app.scan else { return false };
    let Some(active_run_id) = scan.run_id.as_deref() else {
        return false;
    };
    short(active_run_id) == short(run_id)
}

fn past_run_style(status: PastRunStatus) -> Style {
    match status {
        PastRunStatus::Complete => theme::success(),
        PastRunStatus::Running => theme::warn(),
        PastRunStatus::Partial | PastRunStatus::Paused => theme::warn(),
        PastRunStatus::Failed => theme::danger(),
        PastRunStatus::Unknown => theme::muted(),
    }
}

fn finding_count_label(findings: Option<u64>) -> String {
    findings
        .map(|count| count.to_string())
        .unwrap_or_else(|| "—".to_string())
}
