use super::*;
use crate::ui_view_models::{
    jobs_registry_model, JobHistoryState, JobRow, JobRunStatus, JobsRegistryModel,
};

const JOBS_COLUMN_WIDTHS: [usize; 6] = [10, 8, 13, 8, 20, 8];

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
            "run ref",
            "kind",
            "status",
            "elapsed",
            "step / tool",
            "findings",
            "target",
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
    fit_table_widths(
        area.width as usize,
        [run_id, kind, status, elapsed, step, findings, 32],
        [6, 3, 5, 3, 4, 1, 6],
    )
}

fn job_row_line(row: &JobRow, widths: &[usize; 7]) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!(
                "{}  ",
                pad(&crate::app::compact_run_reference(&row.run_id), widths[0])
            ),
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
            format!(
                "{}  ",
                pad(&fit(&step_or_tool_label(row), widths[4]), widths[4])
            ),
            theme::primary(),
        ),
        Span::styled(
            format!("{}  ", pad(&findings_label(row), widths[5])),
            theme::primary(),
        ),
        Span::styled(pad(&fit(&row.target, widths[6]), widths[6]), theme::muted()),
    ])
}

fn elapsed_label(row: &JobRow) -> String {
    row.elapsed_secs
        .map(crate::app::compact_secs)
        .unwrap_or_else(|| "—".to_string())
}

fn step_or_tool_label(row: &JobRow) -> String {
    row.phase
        .clone()
        .filter(|phase| !phase.trim().is_empty())
        .unwrap_or_else(|| row.label.clone())
}

fn findings_label(row: &JobRow) -> String {
    row.findings
        .map(|count| count.to_string())
        .unwrap_or_else(|| "—".to_string())
}

fn job_status_style(status: JobRunStatus) -> Style {
    match status {
        JobRunStatus::Running => theme::success(),
        JobRunStatus::Canceling => theme::warn(),
        JobRunStatus::WaitingInput => theme::warn(),
        JobRunStatus::Queued => theme::warn(),
        JobRunStatus::Completed => theme::success(),
        JobRunStatus::Partial | JobRunStatus::Interrupted => theme::warn(),
        JobRunStatus::Failed | JobRunStatus::Malformed => theme::danger(),
        JobRunStatus::Canceled => theme::warn(),
        // Stale (unverified disk `running`) reads muted, not confident green.
        JobRunStatus::Stale | JobRunStatus::Skipped | JobRunStatus::Unknown => theme::muted(),
    }
}

fn past_run_limit(area: Rect) -> usize {
    (area.height.saturating_sub(8) as usize).clamp(5, 20)
}

fn append_jobs_footer(lines: &mut Vec<Line<'static>>, model: &JobsRegistryModel, area: Rect) {
    if model.rows.is_empty() {
        append_empty_jobs(lines, model);
        return;
    }
    lines.push(blank());
    append_history_status(lines, &model.history_state);
    if model.live_count == 0 {
        lines.push(Line::styled(
            "  no live jobs — recent runs shown; start work with `scan` or `run <tool>`",
            theme::muted(),
        ));
    }
    lines.push(command_list_line(
        &[
            "jobs -k <id>",
            "resume <id>",
            "trace <id>",
            "replay <id>",
            "background",
            "runs",
            "back",
        ],
        area.width as usize,
    ));
}

fn append_history_status(lines: &mut Vec<Line<'static>>, state: &JobHistoryState) {
    let message = match state {
        JobHistoryState::NoTarget => "  recent run history unavailable — select a target".into(),
        JobHistoryState::NotRequested => "  recent run history is not loaded yet".into(),
        JobHistoryState::Loading => "  loading recent run history…".into(),
        JobHistoryState::Failed(error) => {
            format!("  recent run history unavailable — {error}")
        }
        JobHistoryState::Ready => return,
    };
    lines.push(Line::styled(message, theme::muted()));
}

fn append_empty_jobs(lines: &mut Vec<Line<'static>>, model: &JobsRegistryModel) {
    match &model.history_state {
        JobHistoryState::Ready => append_ready_empty_jobs(lines, model.runs_root_hint),
        JobHistoryState::Loading => append_loading_jobs(lines, model.runs_root_hint),
        JobHistoryState::NotRequested => append_unrequested_jobs(lines, model.runs_root_hint),
        JobHistoryState::NoTarget => append_targetless_jobs(lines),
        JobHistoryState::Failed(error) => append_failed_jobs(lines, error),
    }
}

fn append_ready_empty_jobs(lines: &mut Vec<Line<'static>>, runs_root: &str) {
    let detail = format!("live jobs appear here while running; history loaded from {runs_root}.");
    lines.extend(empty_state_panel(
        "no jobs yet",
        &[&detail, "this workspace has not run a module yet."],
        &[
            (
                "scan",
                "start a background scan · streams into this registry",
            ),
            (
                "run <tool>",
                "queue more with `queue <tool>` while one runs",
            ),
        ],
    ));
}

fn append_loading_jobs(lines: &mut Vec<Line<'static>>, runs_root: &str) {
    let detail = format!("reading a bounded recent page from {runs_root}.");
    lines.extend(empty_state_panel(
        "loading recent runs",
        &[&detail, "live jobs will still appear immediately."],
        &[("back", "return while history loads")],
    ));
}

fn append_unrequested_jobs(lines: &mut Vec<Line<'static>>, runs_root: &str) {
    let detail = format!("recent runs from {runs_root} are not loaded yet.");
    lines.extend(empty_state_panel(
        "run history pending",
        &[&detail, "the shell schedules it outside the paint path."],
        &[("back", "return to the previous view")],
    ));
}

fn append_targetless_jobs(lines: &mut Vec<Line<'static>>) {
    lines.extend(empty_state_panel(
        "no target selected",
        &["live jobs appear here immediately; run history is target-scoped."],
        &[("target <path>", "select a workspace to load recent runs")],
    ));
}

fn append_failed_jobs(lines: &mut Vec<Line<'static>>, error: &str) {
    lines.extend(empty_state_panel(
        "recent run history unavailable",
        &[error, "live jobs still appear immediately."],
        &[("back", "return while the run-history issue is resolved")],
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::ViewHydrationKey;
    use crate::ui_view_models::JobSource;
    use kuzushi_core::{write_run_summary, RunSummary, V2Config};

    fn line_width(line: &Line<'_>) -> usize {
        line.spans
            .iter()
            .map(|span| display_width(span.content.as_ref()))
            .sum()
    }

    #[test]
    fn job_columns_fit_narrow_area_budgets() {
        let row = JobRow {
            run_id: "run-日本語-123456".to_string(),
            kind: "agent".to_string(),
            label: "sast:scan".to_string(),
            status: JobRunStatus::WaitingInput,
            elapsed_secs: Some(123),
            phase: Some("collecting evidence".to_string()),
            findings: Some(42),
            target: "/long/日本語/target".to_string(),
            source: JobSource::Live,
            cancelable: true,
        };
        for width in [40, 60, 80] {
            let widths = column_widths(Rect::new(0, 0, width, 20));
            let line = job_row_line(&row, &widths);

            assert_eq!(table_width(&widths), width as usize);
            assert!(line_width(&line) <= width as usize);
        }
    }

    #[test]
    fn durable_job_uses_tool_identity_when_it_has_no_live_step() {
        let mut row = JobRow {
            run_id: "tool-example".to_string(),
            kind: "tool".to_string(),
            label: "sast:scan".to_string(),
            status: JobRunStatus::Canceled,
            elapsed_secs: Some(2),
            phase: None,
            findings: None,
            target: "/tmp/example".to_string(),
            source: JobSource::Disk,
            cancelable: false,
        };

        assert_eq!(step_or_tool_label(&row), "sast:scan");
        row.phase = Some("collecting evidence".to_string());
        assert_eq!(step_or_tool_label(&row), "collecting evidence");
    }

    #[test]
    fn jobs_render_reports_loading_history_without_reading_it() {
        let temp = tempfile::tempdir().unwrap();
        let run_id = "run-stale-loading";
        let summary = RunSummary::running(run_id, "tool", None, "target").with_process_id(u32::MAX);
        write_run_summary(temp.path(), &summary).unwrap();
        let run_dir = crate::ui_view_models::ui_run_dir(Some(temp.path()), run_id);
        let summary_path = run_dir.join("run.json");
        let before_summary = std::fs::read(&summary_path).unwrap();
        let before_names = run_directory_names(&run_dir);
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.workbench_cache()
            .borrow_mut()
            .mark_view_hydration_loading(temp.path(), &[ViewHydrationKey::RunSummaryEntries]);

        let text = rendered_jobs_text(&app);

        assert!(text.contains("loading recent runs"), "{text}");
        assert!(!text.contains("no jobs yet"), "{text}");
        assert_eq!(std::fs::read(summary_path).unwrap(), before_summary);
        assert_eq!(run_directory_names(&run_dir), before_names);
    }

    #[test]
    fn jobs_render_does_not_repair_a_cold_stale_summary() {
        let temp = tempfile::tempdir().unwrap();
        let run_id = "run-stale-paint";
        let summary = RunSummary::running(run_id, "tool", None, "target").with_process_id(u32::MAX);
        write_run_summary(temp.path(), &summary).unwrap();
        let run_dir = crate::ui_view_models::ui_run_dir(Some(temp.path()), run_id);
        let summary_path = run_dir.join("run.json");
        let before_summary = std::fs::read(&summary_path).unwrap();
        let before_names = run_directory_names(&run_dir);
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));

        let text = rendered_jobs_text(&app);

        assert!(text.contains("run history pending"), "{text}");
        assert_eq!(std::fs::read(summary_path).unwrap(), before_summary);
        assert_eq!(run_directory_names(&run_dir), before_names);
    }

    #[test]
    fn jobs_render_calls_a_hydrated_empty_history_empty_state() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_view_keys_blocking(temp.path(), vec![ViewHydrationKey::RunSummaryEntries]);

        let text = rendered_jobs_text(&app);

        assert!(text.contains("no jobs yet"), "{text}");
        assert!(!text.contains("loading recent runs"), "{text}");
    }

    fn rendered_jobs_text(app: &ShellApp) -> String {
        jobs_lines(app, Rect::new(0, 0, 120, 36))
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn run_directory_names(path: &std::path::Path) -> Vec<std::ffi::OsString> {
        let mut names = std::fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        names
    }
}
