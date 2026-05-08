use super::*;

pub(crate) fn workspace_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let view = &app.workspace_view;

    lines.push(blank());
    lines.push(divider("WORKSPACE", area.width));
    lines.push(detail("status", &fit(&view.status, value_width(area, 10))));
    lines.push(detail(
        "target",
        &view
            .root
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| "none".to_string()),
    ));
    lines.push(detail(
        "state",
        &view
            .state_dir
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| ".kuzushi/v2".to_string()),
    ));
    lines.push(detail(
        "findings db",
        &view
            .findings_db
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| ".kuzushi/v2/findings.sqlite3".to_string()),
    ));
    lines.push(detail(
        "findings",
        &view
            .findings_count
            .map(|count| count.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
    ));
    lines.push(detail(
        "last export",
        &view
            .last_export
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| "none".to_string()),
    ));

    if view.root.is_none() {
        lines.push(blank());
        // Empty state per `design/mockups/empty-states.jsx::panel` —
        // operator hasn't picked a workspace yet, so spell out the two
        // canonical entry points.
        lines.extend(empty_state_panel(
            "no workspace selected",
            &[
                "kuzushi anchors all state under <target>/.kuzushi/.",
                "pick a target before running modules.",
            ],
            &[
                (
                    "scan <target>",
                    "scan + remember <target> as the active workspace",
                ),
                (
                    "kuzushi shell --target .",
                    "launch with the current dir as workspace",
                ),
            ],
        ));
    }

    // Severity rollup bar — see `design/mockups/workspace.jsx::rollupBar`.
    // Surfaces the persisted-findings distribution at a glance so an
    // operator landing on `/workspace` sees the shape of the work without
    // jumping into `/findings` first.
    let total = app.findings.len();
    if total > 0 {
        let counts = SeverityCounts::from_findings(&app.findings);
        lines.push(blank());
        lines.push(divider(
            &format!("FINDINGS ROLLUP · {total} persisted"),
            area.width,
        ));
        for (label, n, severity) in [
            ("CRITICAL", counts.critical, Severity::Critical),
            ("HIGH    ", counts.high, Severity::High),
            ("MEDIUM  ", counts.medium, Severity::Medium),
            ("LOW     ", counts.low, Severity::Low),
        ] {
            lines.push(severity_rollup_bar(label, n, total, severity));
        }
    }

    lines.push(blank());
    lines.push(command_list_line(
        &[
            "workspace status",
            "workspace export findings <path>.json",
            "kuzushi pr-comment",
        ],
        area.width as usize,
    ));
    lines
}
