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
        &["workspace scope init", "workspace export findings <path>"],
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
    severity_rollup_bar(row.label, row.count, row.total, row.severity_tone)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{Finding, Severity, V2Config};
    use std::path::PathBuf;

    #[test]
    fn workspace_lines_keep_state_identity_and_current_count_at_operator_sizes() {
        let app = workspace_fixture();
        for area in [Rect::new(0, 0, 100, 30), Rect::new(0, 0, 80, 24)] {
            let lines = workspace_lines(&app, area);
            let rendered = lines
                .iter()
                .map(Line::to_string)
                .collect::<Vec<_>>()
                .join("\n");

            assert!(rendered.contains("./.kuzushi/v3"));
            assert!(rendered.contains("./.kuzushi/v3/index.sqlite3"));
            assert!(rendered.contains("FINDINGS ROLLUP · 4 persisted"));
            assert!(rendered
                .lines()
                .any(|line| { line.contains("findings") && line.trim_end().ends_with('4') }));
            assert!(!rendered.contains("findings  none yet"));
            assert!(lines.len() <= area.height as usize);
            assert!(lines
                .iter()
                .all(|line| line.to_string().chars().count() <= area.width as usize));
        }
    }

    fn workspace_fixture() -> ShellApp {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.domain_mut()
            .set_workspace_view(crate::app::WorkspaceView {
                root: Some(PathBuf::from("/tmp/kuzushi-demo")),
                state_dir: Some(PathBuf::from("/tmp/kuzushi-demo/.kuzushi/v3")),
                findings_db: Some(PathBuf::from("/tmp/kuzushi-demo/.kuzushi/v3/index.sqlite3")),
                findings_count: None,
                last_export: None,
                status: "workspace ready".to_string(),
            });
        *app.findings_mut() = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
        ]
        .into_iter()
        .map(|severity| Finding::new_semgrep("rule.demo", "src/lib.rs", 1, None, severity, "demo"))
        .collect();
        app
    }
}
