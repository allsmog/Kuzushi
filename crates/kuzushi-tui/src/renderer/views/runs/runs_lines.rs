use super::*;

pub(crate) fn runs_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("RUNS", area.width));
    let widths = [12usize, 14, 9, value_width(area, 40)];
    lines.push(aligned_header(
        &["runId", "status", "findings", "target"],
        &widths,
    ));

    // Active scan first.
    let mut emitted = 0usize;
    if let Some(scan) = &app.scan {
        let run_id = scan
            .run_id
            .as_deref()
            .map(short)
            .unwrap_or_else(|| "pending".to_string());
        let status_text = scan_status(scan);
        let status_style = if scan.error.is_some() {
            theme::danger()
        } else if scan.running {
            theme::warn()
        } else {
            theme::success()
        };
        lines.push(runs_row(
            &run_id,
            &status_text,
            status_style,
            &scan.findings_count.to_string(),
            &scan.target.display().to_string(),
            &widths,
        ));
        emitted += 1;
    }

    // Past runs from disk: `<target>/.kuzushi/runs/<runId>/`.  Read up to
    // 20 most recent dirs (alphabetical-ish since runIds embed timestamps).
    let runs_root = app
        .target
        .as_deref()
        .map(|t| t.join(".kuzushi/runs"))
        .unwrap_or_else(|| std::path::PathBuf::from(".kuzushi/runs"));
    let mut past_runs: Vec<PastRun> = collect_past_runs(&runs_root);
    past_runs.sort_by(|a, b| b.run_id.cmp(&a.run_id));
    let take = (area.height.saturating_sub(8) as usize).max(5).min(20);
    for past in past_runs.iter().take(take) {
        // Skip the run that's already shown as the active scan.
        if let Some(scan) = &app.scan {
            if scan.run_id.as_deref().map(short).as_deref() == Some(short(&past.run_id).as_str()) {
                continue;
            }
        }
        let style = match past.status_kind {
            PastRunStatus::Complete => theme::success(),
            PastRunStatus::Running => theme::warn(),
            PastRunStatus::Partial | PastRunStatus::Paused => theme::warn(),
            PastRunStatus::Failed => theme::danger(),
            PastRunStatus::Unknown => theme::muted(),
        };
        lines.push(runs_row(
            &short(&past.run_id),
            past.status_label(),
            style,
            &past
                .findings
                .map(|n| n.to_string())
                .unwrap_or_else(|| "—".to_string()),
            &past.target,
            &widths,
        ));
        emitted += 1;
    }

    if emitted == 0 {
        // Empty state mirrors `design/mockups/empty-states.jsx::panel`
        // for the runs ledger (`RUNS · empty`) — every dispatch writes
        // a run dir, so suggest the cheapest first run.
        lines.extend(empty_state_panel(
            "no runs persisted",
            &[
                "every dispatch writes a run dir under .kuzushi/runs/<id>/.",
                "this workspace has not run a module yet.",
            ],
            &[
                ("scan", "first run will land at .kuzushi/runs/<id>/"),
                ("use context", "cheapest first run · indexes the workspace"),
            ],
        ));
    } else {
        lines.push(blank());
        lines.push(command_list_line(
            &["replay <runId>", "trace <runId>", "findings", "back"],
            area.width as usize,
        ));
    }
    lines
}
