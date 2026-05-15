use super::{sast_tasks_model, ModuleRunSummary};
use crate::ShellApp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleProgressModel {
    pub(crate) section: ModuleProgressSection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ModuleProgressSection {
    RealScan { rows: Vec<ModuleProgressRow> },
    SelectedSast { rows: Vec<ModuleProgressRow> },
    SastPipeline,
    ContextBuild,
    GenericTool { module: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleProgressRow {
    pub(crate) label: String,
    pub(crate) done: usize,
    pub(crate) total: usize,
    pub(crate) status: &'static str,
    pub(crate) kind: ModuleProgressKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModuleProgressKind {
    Done,
    Active,
    Queued,
}

pub(crate) fn module_progress_model(
    app: &ShellApp,
    summary: &ModuleRunSummary,
) -> ModuleProgressModel {
    let focused_module = app.focused_module.as_deref();
    let show_sast_tasks = selected_sast_tasks_are_visible(app, summary, focused_module);

    if show_sast_tasks {
        if let Some(progress) = app.scan_progress.as_ref() {
            return ModuleProgressModel {
                section: ModuleProgressSection::RealScan {
                    rows: real_scan_rows(progress, summary.findings),
                },
            };
        }
        return ModuleProgressModel {
            section: ModuleProgressSection::SelectedSast {
                rows: selected_sast_rows(app, summary),
            },
        };
    }

    ModuleProgressModel {
        section: fallback_section(focused_module, summary),
    }
}

fn selected_sast_tasks_are_visible(
    app: &ShellApp,
    summary: &ModuleRunSummary,
    focused_module: Option<&str>,
) -> bool {
    focused_module == Some("sast")
        && (summary.scan_running || summary.scan_done)
        && sast_tasks_model(app).rows.iter().any(|row| row.selected)
}

fn real_scan_rows(
    progress: &kuzushi_core::ScanProgress,
    findings: usize,
) -> Vec<ModuleProgressRow> {
    let mut rows = progress
        .per_task
        .iter()
        .map(|(task_id, (done, total))| progress_row(task_id, *done, *total))
        .collect::<Vec<_>>();
    rows.push(triage_row(findings));
    rows
}

fn selected_sast_rows(app: &ShellApp, summary: &ModuleRunSummary) -> Vec<ModuleProgressRow> {
    let mut rows = sast_tasks_model(app)
        .rows
        .into_iter()
        .filter(|row| row.selected)
        .map(|row| selected_sast_row(row.task_id, summary.scan_done))
        .collect::<Vec<_>>();
    rows.push(triage_row(summary.findings));
    rows
}

fn fallback_section(
    focused_module: Option<&str>,
    summary: &ModuleRunSummary,
) -> ModuleProgressSection {
    if focused_module == Some("sast") || summary.has_scan {
        return ModuleProgressSection::SastPipeline;
    }
    if focused_module == Some("context") {
        return ModuleProgressSection::ContextBuild;
    }
    ModuleProgressSection::GenericTool {
        module: focused_module.unwrap_or("tool").to_string(),
    }
}

fn progress_row(label: &str, done: usize, total: usize) -> ModuleProgressRow {
    let (kind, status) = progress_state(done, total);
    ModuleProgressRow {
        label: label.to_string(),
        done,
        total,
        status,
        kind,
    }
}

fn selected_sast_row(label: &'static str, scan_done: bool) -> ModuleProgressRow {
    if scan_done {
        return ModuleProgressRow {
            label: label.to_string(),
            done: 1,
            total: 1,
            status: "done",
            kind: ModuleProgressKind::Done,
        };
    }
    ModuleProgressRow {
        label: label.to_string(),
        done: 0,
        total: 1,
        status: "running…",
        kind: ModuleProgressKind::Active,
    }
}

fn triage_row(findings: usize) -> ModuleProgressRow {
    let has_findings = findings > 0;
    ModuleProgressRow {
        label: "triage".to_string(),
        done: 0,
        total: findings.max(1),
        status: if has_findings {
            "queued after scan"
        } else {
            "waiting for findings"
        },
        kind: if has_findings {
            ModuleProgressKind::Active
        } else {
            ModuleProgressKind::Queued
        },
    }
}

fn progress_state(done: usize, total: usize) -> (ModuleProgressKind, &'static str) {
    if total == 0 {
        (ModuleProgressKind::Queued, "queued")
    } else if done >= total {
        (ModuleProgressKind::Done, "done")
    } else {
        (ModuleProgressKind::Active, "running…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScanPanelState;
    use kuzushi_core::{ScanProgress, V2Config};
    use std::{collections::BTreeMap, path::PathBuf};

    #[test]
    fn module_progress_model_prefers_real_scan_rows() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.focused_module = Some("sast".to_string());
        app.scan = Some(scan_panel(true, 2));
        app.scan_progress = Some(scan_progress());
        let summary = super::super::module_run_summary(&app);

        let model = module_progress_model(&app, &summary);

        let ModuleProgressSection::RealScan { rows } = model.section else {
            panic!("expected real scan rows");
        };
        assert!(rows.iter().any(|row| row.label == "semgrep"));
        assert!(rows.iter().any(|row| row.status == "queued after scan"));
    }

    #[test]
    fn module_progress_model_selects_context_build_section() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.focused_module = Some("context".to_string());
        let summary = super::super::module_run_summary(&app);

        let model = module_progress_model(&app, &summary);

        assert_eq!(model.section, ModuleProgressSection::ContextBuild);
    }

    #[test]
    fn module_progress_model_uses_selected_sast_placeholders() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.focused_module = Some("sast".to_string());
        app.scan = Some(scan_panel(true, 0));
        let summary = super::super::module_run_summary(&app);

        let model = module_progress_model(&app, &summary);

        let ModuleProgressSection::SelectedSast { rows } = model.section else {
            panic!("expected selected SAST rows");
        };
        assert!(rows.iter().any(|row| row.label == "triage"));
        assert!(rows.iter().any(|row| row.status == "running…"));
    }

    fn scan_panel(running: bool, findings_count: usize) -> ScanPanelState {
        ScanPanelState {
            run_id: Some("run-progress".to_string()),
            target: PathBuf::from("./demo"),
            stage: "scanning".to_string(),
            findings_count,
            running,
            abort_requested: false,
            error: None,
        }
    }

    fn scan_progress() -> ScanProgress {
        let mut per_task = BTreeMap::new();
        per_task.insert("semgrep".to_string(), (3, 5));
        ScanProgress {
            total: 5,
            done: 3,
            current_tool: Some("semgrep".to_string()),
            current_target: Some("./demo".to_string()),
            per_task,
        }
    }
}
