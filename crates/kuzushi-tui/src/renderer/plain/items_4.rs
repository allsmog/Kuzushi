use super::prelude::*;
use super::*;

pub(crate) fn plain_context_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let view = &app.context_view;

    lines.push(String::new());
    lines.push(plain_section_divider("CONTEXT", width));
    lines.push(format!(
        "snapshot: {}",
        view.snapshot_path
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| ".kuzushi/context-snapshot.json".to_string())
    ));
    lines.push(format!(
        "state: {}",
        if view.exists { "present" } else { "missing" }
    ));
    lines.push(format!("status: {}", view.status));

    if view.exists {
        lines.push(format!(
            "target: {}",
            view.target.as_deref().unwrap_or("unknown")
        ));
        lines.push(format!(
            "discovery: {}",
            view.discovery.as_deref().unwrap_or("unknown")
        ));
        lines.push(format!(
            "files: indexed={} total={}",
            view.files_indexed
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".to_string()),
            view.total_files
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".to_string())
        ));
        lines.push(format!("languages: {}", join_or_dash(&view.languages)));
        lines.push(format!("frameworks: {}", join_or_dash(&view.frameworks)));
        lines.push(format!(
            "generated: {}",
            join_or_dash(&view.generated_slices)
        ));
        lines.push(format!("stale: {}", join_or_dash(&view.stale_slices)));
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

pub(crate) fn plain_workspace_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let view = &app.workspace_view;

    lines.push(String::new());
    lines.push(plain_section_divider("WORKSPACE", width));
    lines.push(format!("status: {}", view.status));
    lines.push(format!(
        "target: {}",
        view.root
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| "none".to_string())
    ));
    lines.push(format!(
        "state: {}",
        view.state_dir
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| ".kuzushi/v2".to_string())
    ));
    lines.push(format!(
        "findings db: {}",
        view.findings_db
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| ".kuzushi/v2/findings.sqlite3".to_string())
    ));
    lines.push(format!(
        "findings: {}",
        view.findings_count
            .map(|count| count.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    ));
    lines.push(format!(
        "last export: {}",
        view.last_export
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| "none".to_string())
    ));
    if view.root.is_none() {
        lines.push(String::new());
        lines.push(
            "No active workspace. Next: scan <target> or kuzushi shell --target .".to_string(),
        );
    }
    lines.push(String::new());
    lines.push(
        "Next: workspace status, workspace export findings <path>.json, kuzushi pr-comment"
            .to_string(),
    );
    lines
}
