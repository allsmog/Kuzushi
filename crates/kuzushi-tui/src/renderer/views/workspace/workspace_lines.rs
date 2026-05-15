use super::*;
use crate::ui_view_models::{workspace_model, WorkspaceModel, WorkspaceRollupRow};

pub(crate) fn workspace_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = workspace_model(app);

    lines.push(blank());
    lines.push(divider("WORKSPACE", area.width));
    append_workspace_summary(&mut lines, &model, area);
    append_workspace_empty_state(&mut lines, &model);
    append_workspace_rollup(&mut lines, &model, area);

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

fn append_workspace_summary(lines: &mut Vec<Line<'static>>, model: &WorkspaceModel, area: Rect) {
    lines.push(detail("status", &fit(&model.status, value_width(area, 10))));
    lines.push(detail("target", &model.target_label));
    lines.push(detail("state", &model.state_label));
    lines.push(detail("findings db", &model.findings_db_label));
    lines.push(detail("findings", &model.findings_label));
    lines.push(detail("last export", &model.last_export_label));
}

fn append_workspace_empty_state(lines: &mut Vec<Line<'static>>, model: &WorkspaceModel) {
    if !model.empty {
        return;
    }
    lines.push(blank());
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

fn append_workspace_rollup(lines: &mut Vec<Line<'static>>, model: &WorkspaceModel, area: Rect) {
    if model.rollup_rows.is_empty() {
        return;
    }
    lines.push(blank());
    lines.push(divider(
        &format!("FINDINGS ROLLUP · {} persisted", model.rollup_total),
        area.width,
    ));
    for row in &model.rollup_rows {
        lines.push(workspace_rollup_line(row));
    }
}

fn workspace_rollup_line(row: &WorkspaceRollupRow) -> Line<'static> {
    severity_rollup_bar(row.label, row.count, row.total, row.severity)
}
