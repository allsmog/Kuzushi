use super::*;
use crate::ui_view_models::{
    plain_context_model, workspace_model, PlainContextModel, WorkspaceModel,
};

pub(crate) fn plain_context_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let model = plain_context_model(app);

    push_plain_context_summary(&mut lines, &model, width);
    lines
}

fn push_plain_context_summary(lines: &mut Vec<String>, model: &PlainContextModel, width: usize) {
    lines.push(String::new());
    lines.push(plain_section_divider(model.title, width));
    lines.extend(model.summary_rows.iter().cloned());
    lines.extend(model.body_rows.iter().cloned());
    lines.push(String::new());
    lines.push(model.next_hint.to_string());
}

pub(crate) fn plain_workspace_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let model = workspace_model(app);

    lines.push(String::new());
    lines.push(plain_section_divider("WORKSPACE", width));
    push_plain_workspace_summary(&mut lines, &model);
    push_plain_workspace_empty_state(&mut lines, &model);
    lines.push(String::new());
    lines.push(
        "Next: workspace status, workspace export findings <path>.json, kuzushi pr-comment"
            .to_string(),
    );
    lines
}

fn push_plain_workspace_summary(lines: &mut Vec<String>, model: &WorkspaceModel) {
    lines.push(format!("status: {}", model.status));
    lines.push(format!("target: {}", model.target_label));
    lines.push(format!("state: {}", model.state_label));
    lines.push(format!("findings db: {}", model.findings_db_label));
    lines.push(format!("findings: {}", model.findings_label));
    lines.push(format!("last export: {}", model.last_export_label));
}

fn push_plain_workspace_empty_state(lines: &mut Vec<String>, model: &WorkspaceModel) {
    if model.empty {
        lines.push(String::new());
        lines.push(
            "No active workspace. Next: scan <target> or kuzushi shell --target .".to_string(),
        );
    }
}
