use super::{compact_target_path, SeverityCounts, SeverityTone};
use crate::ShellApp;
use kuzushi_core::Finding;
use std::path::Path;
use std::sync::OnceLock;

static FINDINGS_DB_RELATIVE_PATH: OnceLock<String> = OnceLock::new();
static WORKSPACE_STATE_RELATIVE_PATH: OnceLock<String> = OnceLock::new();

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
pub(crate) struct PlainWorkspaceProjection {
    pub(crate) title: &'static str,
    pub(crate) summary_rows: Vec<String>,
    pub(crate) empty_rows: Vec<String>,
    pub(crate) next_hint: &'static str,
}

pub(crate) fn workspace_model(app: &ShellApp) -> WorkspaceModel {
    let view = app.domain().workspace_view();
    let findings = app.findings();
    let loaded_count = findings.len();
    WorkspaceModel {
        status: view.status.clone(),
        target_label: compact_path_or(view.root.as_deref(), "none"),
        state_label: compact_path_or(view.state_dir.as_deref(), workspace_state_relative_path()),
        findings_db_label: compact_path_or(
            view.findings_db.as_deref(),
            findings_db_relative_path(),
        ),
        findings_label: workspace_findings_label(
            loaded_count,
            view.findings_count,
            view.root.is_some(),
        ),
        last_export_label: compact_path_or(view.last_export.as_deref(), "none"),
        empty: view.root.is_none(),
        rollup_total: loaded_count,
        rollup_rows: rollup_rows(findings),
    }
}

pub(crate) fn plain_workspace_projection(app: &ShellApp) -> PlainWorkspaceProjection {
    PlainWorkspaceProjection::from_workspace_model(workspace_model(app))
}

impl PlainWorkspaceProjection {
    fn from_workspace_model(model: WorkspaceModel) -> Self {
        PlainWorkspaceProjection {
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
                "Next: workspace status, workspace scope init, workspace export findings <path> [format] [--completeness open|complete] [--allow-empty]",
        }
    }
}

fn plain_workspace_empty_rows(_empty: bool) -> Vec<String> {
    Vec::new()
}

pub(crate) fn findings_db_relative_path() -> &'static str {
    FINDINGS_DB_RELATIVE_PATH
        .get_or_init(|| {
            kuzushi_core::workspace::workspace_findings_db_path("")
                .display()
                .to_string()
        })
        .as_str()
}

pub(crate) fn workspace_state_relative_path() -> &'static str {
    WORKSPACE_STATE_RELATIVE_PATH
        .get_or_init(|| {
            kuzushi_core::workspace::workspace_state_dir("")
                .display()
                .to_string()
        })
        .as_str()
}

fn compact_path_or(path: Option<&Path>, fallback: &str) -> String {
    path.map(compact_workspace_path)
        .unwrap_or_else(|| fallback.to_string())
}

fn compact_workspace_path(path: &Path) -> String {
    let mut relative = std::path::PathBuf::new();
    let mut in_state = false;
    for component in path.components() {
        in_state |= component.as_os_str() == ".kuzushi";
        if in_state {
            relative.push(component.as_os_str());
        }
    }
    if in_state {
        return format!("./{}", relative.display());
    }
    compact_target_path(&path.display().to_string())
}

fn workspace_findings_label(
    loaded: usize,
    persisted: Option<usize>,
    has_workspace: bool,
) -> String {
    let Some(total) = persisted else {
        return if loaded > 0 {
            loaded.to_string()
        } else if has_workspace {
            "loading".to_string()
        } else {
            "unavailable (select a target)".to_string()
        };
    };
    if total > loaded && loaded > 0 {
        return format!("{loaded}/{total} loaded");
    }
    if total > 0 && loaded == 0 {
        return format!("loading · {total} persisted");
    }
    loaded.max(total).to_string()
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
