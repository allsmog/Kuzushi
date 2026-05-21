use super::{compact_target_path, SeverityCounts, SeverityTone};
use crate::ShellApp;
use kuzushi_core::Finding;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceModel {
    pub(crate) status: String,
    pub(crate) target_label: String,
    pub(crate) state_label: String,
    pub(crate) findings_db_label: String,
    pub(crate) findings_label: String,
    pub(crate) last_export_label: String,
    pub(crate) empty: bool,
    pub(crate) rollup_total: usize,
    pub(crate) rollup_rows: Vec<WorkspaceRollupRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceRollupRow {
    pub(crate) label: &'static str,
    pub(crate) count: usize,
    pub(crate) total: usize,
    pub(crate) severity_tone: SeverityTone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainWorkspaceModel {
    pub(crate) title: &'static str,
    pub(crate) summary_rows: Vec<String>,
    pub(crate) empty_rows: Vec<String>,
    pub(crate) next_hint: &'static str,
}

pub(crate) fn workspace_model(app: &ShellApp) -> WorkspaceModel {
    let view = &app.workspace_view;
    WorkspaceModel {
        status: view.status.clone(),
        target_label: compact_path_or(view.root.as_deref(), "none"),
        state_label: compact_path_or(view.state_dir.as_deref(), ".kuzushi/v2"),
        findings_db_label: compact_path_or(
            view.findings_db.as_deref(),
            ".kuzushi/v2/findings.sqlite3",
        ),
        findings_label: count_or_unknown(view.findings_count),
        last_export_label: compact_path_or(view.last_export.as_deref(), "none"),
        empty: view.root.is_none(),
        rollup_total: app.findings.len(),
        rollup_rows: rollup_rows(&app.findings),
    }
}

pub(crate) fn plain_workspace_model(app: &ShellApp) -> PlainWorkspaceModel {
    PlainWorkspaceModel::from_workspace_model(workspace_model(app))
}

impl PlainWorkspaceModel {
    fn from_workspace_model(model: WorkspaceModel) -> Self {
        PlainWorkspaceModel {
            title: "WORKSPACE",
            summary_rows: vec![
                format!("status: {}", model.status),
                format!("target: {}", model.target_label),
                format!("state: {}", model.state_label),
                format!("findings db: {}", model.findings_db_label),
                format!("findings: {}", model.findings_label),
                format!("last export: {}", model.last_export_label),
            ],
            empty_rows: plain_workspace_empty_rows(model.empty),
            next_hint:
                "Next: workspace status, workspace export findings <path>.json, kuzushi pr-comment",
        }
    }
}

fn plain_workspace_empty_rows(empty: bool) -> Vec<String> {
    if empty {
        vec![
            String::new(),
            "No active workspace. Next: scan <target> or kuzushi shell --target .".to_string(),
        ]
    } else {
        Vec::new()
    }
}

fn compact_path_or(path: Option<&Path>, fallback: &str) -> String {
    path.map(|path| compact_target_path(&path.display().to_string()))
        .unwrap_or_else(|| fallback.to_string())
}

fn count_or_unknown(count: Option<usize>) -> String {
    count
        .map(|count| count.to_string())
        .unwrap_or_else(|| "— (no scan yet)".to_string())
}

fn rollup_rows(findings: &[Finding]) -> Vec<WorkspaceRollupRow> {
    if findings.is_empty() {
        return Vec::new();
    }
    let counts = SeverityCounts::from_findings(findings);
    let total = findings.len();
    vec![
        rollup_row("CRITICAL", counts.critical, total, SeverityTone::Critical),
        rollup_row("HIGH    ", counts.high, total, SeverityTone::High),
        rollup_row("MEDIUM  ", counts.medium, total, SeverityTone::Medium),
        rollup_row("LOW     ", counts.low, total, SeverityTone::Low),
    ]
}

fn rollup_row(
    label: &'static str,
    count: usize,
    total: usize,
    severity_tone: SeverityTone,
) -> WorkspaceRollupRow {
    WorkspaceRollupRow {
        label,
        count,
        total,
        severity_tone,
    }
}

#[cfg(test)]
mod tests;
