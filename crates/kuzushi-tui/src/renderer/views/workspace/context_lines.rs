use super::*;

pub(crate) fn context_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
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
