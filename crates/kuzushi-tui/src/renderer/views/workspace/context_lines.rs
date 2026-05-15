use super::*;
use crate::ui_view_models::{context_snapshot_model, ContextSnapshotDetails};

pub(crate) fn context_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = context_snapshot_model(app);

    lines.push(blank());
    lines.push(divider("CONTEXT", area.width));
    lines.push(detail("snapshot", &model.snapshot));
    lines.push(detail("state", model.state));
    lines.push(detail("status", &fit(&model.status, value_width(area, 10))));

    if let Some(running) = &model.running {
        lines.push(blank());
        lines.push(pipeline_row(running.glyph, &running.tool, running.message));
    } else if let Some(details) = &model.details {
        append_context_details(&mut lines, details, area);
    } else {
        append_missing_context(&mut lines);
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

fn append_context_details(
    lines: &mut Vec<Line<'static>>,
    details: &ContextSnapshotDetails,
    area: Rect,
) {
    lines.push(detail("target", &details.target));
    lines.push(detail("discovery", &details.discovery));
    lines.push(detail("files", &details.files));
    lines.push(detail(
        "languages",
        &fit(&details.languages, value_width(area, 10)),
    ));
    lines.push(detail(
        "frameworks",
        &fit(&details.frameworks, value_width(area, 10)),
    ));
    lines.push(detail(
        "generated",
        &fit(&details.generated, value_width(area, 10)),
    ));
    lines.push(detail("stale", &fit(&details.stale, value_width(area, 10))));
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
