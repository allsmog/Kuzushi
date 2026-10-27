use super::*;
use crate::ui_view_models::{context_snapshot_model, ContextSnapshotDetails};

pub(crate) fn context_page_rows(app: &ShellApp) -> Option<usize> {
    if app.shell_view() != ShellView::Context {
        return None;
    }
    let viewport = app.viewport();
    let primary =
        crate::renderer::primary_body_area(app, Rect::new(0, 0, viewport.columns, viewport.rows));
    let area = crate::ui_view_models::answers_layout(app, primary).workspace;
    Some(usize::from(area.height).max(1))
}

pub(crate) fn context_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = context_snapshot_model(app);

    lines.push(blank());
    lines.push(divider("CONTEXT", area.width));
    lines.extend(detail_wrapped("snapshot", &model.snapshot, area.width));
    lines.push(detail("state", model.state));
    lines.extend(detail_wrapped("status", &model.status, area.width));

    if let Some(running) = &model.running {
        lines.push(blank());
        lines.push(pipeline_row(running.glyph, &running.tool, running.message));
    } else if let Some(details) = &model.details {
        append_context_details(&mut lines, details, area);
    } else if matches!(model.state, "malformed" | "unavailable") {
        lines.extend(detail_wrapped(
            "next",
            "Resolve the index status above, then use context status to retry.",
            area.width,
        ));
    } else {
        append_missing_context(&mut lines);
    }

    lines.push(blank());
    lines.extend(command_list_lines(
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

fn append_context_details(
    lines: &mut Vec<Line<'static>>,
    details: &ContextSnapshotDetails,
    area: Rect,
) {
    for (label, value) in [
        ("target", &details.target),
        ("discovery", &details.discovery),
        ("files", &details.files),
        ("languages", &details.languages),
        ("frameworks", &details.frameworks),
        ("generated", &details.generated),
        ("stale", &details.stale),
    ] {
        lines.extend(detail_wrapped(label, value, area.width));
    }
    lines.push(blank());
    lines.extend(details.inspection.iter().flat_map(|line| {
        wrap_text(line, area.width as usize)
            .into_iter()
            .map(Line::from)
    }));
}

fn append_missing_context(lines: &mut Vec<Line<'static>>) {
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

#[cfg(test)]
mod tests;
