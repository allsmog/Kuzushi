use super::*;

pub(in crate::renderer) fn context_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let view = &app.context_view;
    let context_tool_running = app
        .running_tool_name()
        .filter(|tool| matches!(*tool, "context:build" | "context-lite:index"));

    lines.push(blank());
    lines.push(divider("CONTEXT", area.width));
    lines.push(detail(
        "snapshot",
        &view
            .snapshot_path
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| ".kuzushi/context-snapshot.json".to_string()),
    ));
    lines.push(detail(
        "state",
        if view.exists { "present" } else { "missing" },
    ));
    if let Some(tool_name) = context_tool_running {
        lines.push(detail(
            "status",
            &fit(
                &format!(
                    "{} {tool_name} indexing repository context",
                    app.spinner_glyph()
                ),
                value_width(area, 10),
            ),
        ));
    } else {
        lines.push(detail("status", &fit(&view.status, value_width(area, 10))));
    }

    if let Some(tool_name) = context_tool_running {
        lines.push(blank());
        lines.push(pipeline_row(
            "⏵",
            tool_name,
            "building snapshot; this view updates when the worker finishes",
        ));
    } else if view.exists {
        lines.push(detail(
            "target",
            view.target.as_deref().unwrap_or("unknown"),
        ));
        lines.push(detail(
            "discovery",
            view.discovery.as_deref().unwrap_or("unknown"),
        ));
        lines.push(detail(
            "files",
            &format!(
                "indexed={} total={}",
                view.files_indexed
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "?".to_string()),
                view.total_files
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "?".to_string())
            ),
        ));
        lines.push(detail(
            "languages",
            &fit(&join_or_dash(&view.languages), value_width(area, 10)),
        ));
        lines.push(detail(
            "frameworks",
            &fit(&join_or_dash(&view.frameworks), value_width(area, 10)),
        ));
        lines.push(detail(
            "generated",
            &fit(&join_or_dash(&view.generated_slices), value_width(area, 10)),
        ));
        lines.push(detail(
            "stale",
            &fit(&join_or_dash(&view.stale_slices), value_width(area, 10)),
        ));
    } else {
        lines.push(blank());
        lines.extend(empty_state_panel(
            "no context snapshot yet",
            &[
                "context indexes the workspace into .kuzushi/context-snapshot.json.",
                "every SAST module reads the snapshot for structure.",
            ],
            &[
                ("context build", "write the full snapshot"),
                (
                    "context status",
                    "inspect freshness if you think one exists",
                ),
            ],
        ));
    }

    lines.push(blank());
    lines.push(command_list_line(
        &[
            "context build",
            "context status",
            "context regen repo",
            "context regen app-model",
        ],
        area.width as usize,
    ));
    lines
}

pub(in crate::renderer) fn workspace_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
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

/// Chat bubble tag header matching `design/mockups/agent-chat.jsx::bubble`:
///
///   ` <tag> ──────────────────────────...──`
///
/// `tag_style` carries the role tint (`c-accent` for the operator side,
/// `c-success` for the agent side, `c-danger` for errors).

pub(in crate::renderer) fn severity_rollup_bar(
    label: &str,
    n: usize,
    total: usize,
    severity: Severity,
) -> Line<'static> {
    let bar_w: usize = 28;
    let filled = if total == 0 {
        0
    } else {
        ((bar_w * n) as f64 / total as f64).round() as usize
    };
    let filled = filled.clamp(if n > 0 { 1 } else { 0 }, bar_w);
    let empty = bar_w - filled;
    Line::from(vec![
        Span::raw(" "),
        Span::styled(label.to_string(), theme::severity(severity)),
        Span::styled(" [".to_string(), theme::subtle()),
        Span::styled("█".repeat(filled), theme::severity(severity)),
        Span::styled("░".repeat(empty), theme::subtle()),
        Span::styled("] ".to_string(), theme::subtle()),
        Span::styled(format!("{n:>3}"), theme::primary()),
        Span::styled("/".to_string(), theme::subtle()),
        Span::styled(total.to_string(), theme::muted()),
    ])
}

pub(in crate::renderer) fn knowledge_base_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let module_id = app.kb_view.module_id.as_str();
    let attachments = app
        .kb_view
        .attachments
        .iter()
        .filter(|record| record.module_id == module_id)
        .collect::<Vec<_>>();
    let store = app
        .kb_view
        .store_path
        .as_ref()
        .map(|path| compact_target_path(&path.display().to_string()))
        .unwrap_or_else(|| ".kuzushi/v2/attachments.json".to_string());

    lines.push(blank());
    lines.push(divider("KB ATTACHMENTS", area.width));
    lines.push(detail("module", module_id));
    lines.push(detail("store", &store));
    lines.push(detail(
        "supported",
        &SUPPORTED_ATTACHMENT_MODULES.join(", "),
    ));
    lines.push(blank());

    lines.push(divider("KNOWN ARTIFACTS", area.width));
    if app.kb_view.artifacts.is_empty() {
        lines.push(muted("No known Rust artifacts for this module."));
    } else {
        lines.push(table_header(
            &["state", "path", "description"],
            &kb_artifact_widths(area.width),
        ));
        let widths = kb_artifact_widths(area.width);
        for artifact in &app.kb_view.artifacts {
            lines.push(table_row(
                &[
                    if artifact.exists {
                        "present"
                    } else {
                        "missing"
                    },
                    &fit(&artifact.path, widths.get(1).copied().unwrap_or(24)),
                    &fit(&artifact.description, widths.get(2).copied().unwrap_or(20)),
                ],
                &widths,
            ));
        }
    }

    lines.push(blank());
    if attachments.is_empty() {
        lines.push(divider("ATTACHED · empty", area.width));
        lines.extend(empty_state_panel(
            "no attachments yet",
            &[
                "kuzushi indexes attachments under .kuzushi/v2/artifact-kb.sqlite3.",
                "this module has no path or URL attachments bound.",
            ],
            &[
                (
                    "attach <path>",
                    "add a workspace-relative file or directory",
                ),
                ("attach https://...", "add a URL · metadata-only by default"),
                ("kb pull kev", "preload the KEV / NVD / CWE catalogs"),
            ],
        ));
    } else {
        lines.push(divider("ATTACHED", area.width));
        lines.push(table_header(
            &["id", "kind", "source", "status"],
            &kb_attachment_widths(area.width),
        ));
        let widths = kb_attachment_widths(area.width);
        for record in attachments {
            let kind = match &record.kind {
                AttachmentKind::Path => "path",
                AttachmentKind::Url => "url",
            };
            lines.push(table_row(
                &[
                    &record.id,
                    kind,
                    &fit(&record.source, widths.get(2).copied().unwrap_or(22)),
                    &fit(&record.status, widths.get(3).copied().unwrap_or(18)),
                ],
                &widths,
            ));
        }
    }
    lines.push(blank());
    lines.push(command_list_line(
        &[
            "kb [module]",
            "attach <path-or-url>",
            "detach <id>",
            "reparse <id>",
        ],
        area.width as usize,
    ));
    lines
}

pub(in crate::renderer) fn kb_artifact_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let state = 7;
    let path = if total < 88 { 30 } else { 42 };
    let gaps = 4;
    let description = total.saturating_sub(state + path + gaps).max(16);
    vec![state, path, description]
}

pub(in crate::renderer) fn kb_attachment_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let id = 14;
    let kind = 4;
    let source = if total < 88 { 24 } else { 36 };
    let gaps = 6;
    let status = total.saturating_sub(id + kind + source + gaps).max(16);
    vec![id, kind, source, status]
}
