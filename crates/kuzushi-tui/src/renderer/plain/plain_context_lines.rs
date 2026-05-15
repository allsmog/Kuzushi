use super::*;
use crate::ui_view_models::{
    context_snapshot_model, workspace_model, ContextSnapshotDetails, WorkspaceModel,
};

pub(crate) fn plain_context_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let model = context_snapshot_model(app);

    lines.push(String::new());
    lines.push(plain_section_divider("CONTEXT", width));
    lines.push(format!("snapshot: {}", model.snapshot));
    lines.push(format!("state: {}", model.state));
    lines.push(format!("status: {}", model.status));

    if let Some(details) = &model.details {
        push_plain_context_details(&mut lines, details);
    } else {
        lines.push(String::new());
        lines.push(
            "No context snapshot exists yet. Next: context build writes .kuzushi/context-snapshot.json."
                .to_string(),
        );
    }

    lines.push(String::new());
    lines.push("Next: context build, context status, context regen repo".to_string());
    lines
}

fn push_plain_context_details(lines: &mut Vec<String>, details: &ContextSnapshotDetails) {
    lines.push(format!("target: {}", details.target));
    lines.push(format!("discovery: {}", details.discovery));
    lines.push(format!("files: {}", details.files));
    lines.push(format!("languages: {}", details.languages));
    lines.push(format!("frameworks: {}", details.frameworks));
    lines.push(format!("generated: {}", details.generated));
    lines.push(format!("stale: {}", details.stale));
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
