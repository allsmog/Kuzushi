use super::*;
use crate::ui_view_models::{context_snapshot_model, ContextSnapshotDetails};

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

    lines.push(String::new());
    lines.push(plain_section_divider("WORKSPACE", width));
    push_plain_workspace_summary(&mut lines, &app.workspace_view);
    push_plain_workspace_empty_state(&mut lines, &app.workspace_view);
    lines.push(String::new());
    lines.push(
        "Next: workspace status, workspace export findings <path>.json, kuzushi pr-comment"
            .to_string(),
    );
    lines
}

fn push_plain_workspace_summary(lines: &mut Vec<String>, view: &crate::app::WorkspaceView) {
    lines.push(format!("status: {}", view.status));
    lines.push(format!(
        "target: {}",
        compact_path_or(view.root.as_deref(), "none")
    ));
    lines.push(format!(
        "state: {}",
        compact_path_or(view.state_dir.as_deref(), ".kuzushi/v2")
    ));
    lines.push(format!(
        "findings db: {}",
        compact_path_or(view.findings_db.as_deref(), ".kuzushi/v2/findings.sqlite3")
    ));
    lines.push(format!(
        "findings: {}",
        view.findings_count
            .map(|count| count.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    ));
    lines.push(format!(
        "last export: {}",
        compact_path_or(view.last_export.as_deref(), "none")
    ));
}

fn compact_path_or(path: Option<&std::path::Path>, fallback: &str) -> String {
    path.map(|path| compact_target_path(&path.display().to_string()))
        .unwrap_or_else(|| fallback.to_string())
}

fn push_plain_workspace_empty_state(lines: &mut Vec<String>, view: &crate::app::WorkspaceView) {
    if view.root.is_none() {
        lines.push(String::new());
        lines.push(
            "No active workspace. Next: scan <target> or kuzushi shell --target .".to_string(),
        );
    }
}
