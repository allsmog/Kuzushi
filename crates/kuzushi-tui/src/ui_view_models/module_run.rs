use super::{compact_target_path, scan_status};
use crate::{ScanPanelState, ShellApp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleRunSummary {
    pub(crate) target: String,
    pub(crate) stage: String,
    pub(crate) findings: usize,
    pub(crate) findings_label: String,
    pub(crate) run: String,
    pub(crate) active_stage: String,
    pub(crate) status: ModuleRunStatusKind,
    pub(crate) spinner_phase: usize,
    pub(crate) scan_running: bool,
    pub(crate) scan_done: bool,
    pub(crate) has_scan: bool,
    pub(crate) running_tool: Option<String>,
    pub(crate) scan_error: Option<String>,
}

impl ModuleRunSummary {
    pub(crate) fn tool_is_running(&self) -> bool {
        self.running_tool.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleRunLiveActivity {
    pub(crate) phase_label: &'static str,
    pub(crate) subject: String,
    pub(crate) detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModuleRunStatusKind {
    Idle,
    Running,
    Aborting,
    Failed,
    Done,
}

pub(crate) fn module_run_summary(app: &ShellApp) -> ModuleRunSummary {
    let scan = app.scan();
    let running_tool = app.running_tool_name().map(str::to_string);
    let scan_running = scan.is_some_and(|scan| scan.running);

    ModuleRunSummary {
        target: module_run_target(app, scan),
        stage: module_run_stage(app, scan, running_tool.as_ref()),
        findings: module_run_findings(app, scan),
        findings_label: module_run_findings_label(app, scan, running_tool.as_ref()),
        run: module_run_label(scan, running_tool.as_deref()),
        active_stage: module_run_active_stage(scan),
        status: module_run_status(scan, running_tool.as_deref()),
        spinner_phase: app.ui().spinner_phase() as usize,
        scan_running,
        scan_done: module_run_done(scan, scan_running),
        has_scan: scan.is_some(),
        running_tool,
        scan_error: scan.and_then(|scan| scan.error.clone()),
    }
}

pub(crate) fn module_run_live_activity(app: &ShellApp) -> Option<ModuleRunLiveActivity> {
    let activity = app.live_activity()?;
    if !activity.phase.active() {
        return None;
    }
    Some(ModuleRunLiveActivity {
        phase_label: activity.phase.label(),
        subject: activity.subject.clone(),
        detail: activity.detail.clone(),
    })
}

fn module_run_target(app: &ShellApp, scan: Option<&ScanPanelState>) -> String {
    scan.map(|scan| compact_target_path(&scan.target.display().to_string()))
        .or_else(|| {
            app.target()
                .map(|path| compact_target_path(&path.display().to_string()))
        })
        .unwrap_or_else(|| "target:none".to_string())
}

fn module_run_stage(
    app: &ShellApp,
    scan: Option<&ScanPanelState>,
    running_tool: Option<&String>,
) -> String {
    scan.map(scan_status)
        .or_else(|| {
            app.live_activity()
                .map(|activity| activity.phase.label().to_string())
        })
        .or_else(|| running_tool.map(|_| "running tool".to_string()))
        .unwrap_or_else(|| "idle".to_string())
}

fn module_run_findings(app: &ShellApp, scan: Option<&ScanPanelState>) -> usize {
    scan.map(|scan| scan.findings_count)
        .unwrap_or(app.findings_total_count())
}

fn module_run_findings_label(
    app: &ShellApp,
    scan: Option<&ScanPanelState>,
    running_tool: Option<&String>,
) -> String {
    if scan.is_some_and(|scan| scan.running) {
        return "findings pending".to_string();
    }
    if running_tool.is_some() && scan.is_none() {
        return "findings unknown".to_string();
    }
    let count = module_run_findings(app, scan);
    if scan.is_none() && app.findings_are_partial() {
        return format!("{} of {count} findings loaded", app.findings().len());
    }
    format!("{} {}", count, module_run_finding_noun(count))
}

fn module_run_finding_noun(count: usize) -> &'static str {
    if count == 1 {
        "finding"
    } else {
        "findings"
    }
}

fn module_run_label(scan: Option<&ScanPanelState>, running_tool: Option<&str>) -> String {
    scan.and_then(|scan| scan.run_id.as_ref())
        .map(|run_id| format!("run {}", short_run_id(run_id)))
        .unwrap_or_else(|| run_label_without_id(scan.is_some(), running_tool))
}

fn module_run_active_stage(scan: Option<&ScanPanelState>) -> String {
    scan.map(|scan| scan.stage.clone())
        .unwrap_or_else(|| "idle".to_string())
}

fn module_run_done(scan: Option<&ScanPanelState>, scan_running: bool) -> bool {
    scan.is_some() && !scan_running && scan.and_then(|scan| scan.error.as_ref()).is_none()
}

fn module_run_status(
    scan: Option<&ScanPanelState>,
    running_tool: Option<&str>,
) -> ModuleRunStatusKind {
    match scan {
        Some(scan) if scan.running && scan.abort_requested => ModuleRunStatusKind::Aborting,
        Some(scan) if scan.running => ModuleRunStatusKind::Running,
        Some(scan) if scan.error.is_some() => ModuleRunStatusKind::Failed,
        Some(_) => ModuleRunStatusKind::Done,
        None if running_tool.is_some() => ModuleRunStatusKind::Running,
        None => ModuleRunStatusKind::Idle,
    }
}

fn run_label_without_id(has_scan: bool, running_tool: Option<&str>) -> String {
    if has_scan {
        "run pending".to_string()
    } else if let Some(tool_name) = running_tool {
        tool_name.to_string()
    } else {
        "tool run".to_string()
    }
}

fn short_run_id(value: &str) -> String {
    value.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LiveActivity, LiveActivityPhase};
    use kuzushi_core::{Finding, Severity, V2Config};
    use std::path::PathBuf;

    #[test]
    fn module_run_summary_describes_idle_state() {
        let app = ShellApp::new(V2Config::default(), None);

        let summary = module_run_summary(&app);

        assert_eq!(summary.target, "target:none");
        assert_eq!(summary.stage, "idle");
        assert_eq!(summary.findings, 0);
        assert_eq!(summary.findings_label, "0 findings");
        assert_eq!(summary.run, "tool run");
        assert_eq!(summary.status, ModuleRunStatusKind::Idle);
        assert!(!summary.has_scan);
        assert!(!summary.tool_is_running());
    }

    #[test]
    fn module_run_summary_prefers_scan_state() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_scan_panel(Some(ScanPanelState {
            run_id: Some("run-abcdef123".to_string()),
            target: PathBuf::from("./demo"),
            stage: "scanning".to_string(),
            findings_count: 3,
            running: true,
            abort_requested: false,
            error: None,
        }));
        *app.findings_mut() = vec![Finding::new_semgrep(
            "demo.rule",
            "src/app.rs",
            1,
            None,
            Severity::High,
            "stored finding",
        )];

        let summary = module_run_summary(&app);

        assert_eq!(summary.target, "./demo");
        assert_eq!(summary.stage, "running: scanning");
        assert_eq!(summary.findings, 3);
        assert_eq!(summary.findings_label, "findings pending");
        assert_eq!(summary.run, "run run-abcd");
        assert_eq!(summary.status, ModuleRunStatusKind::Running);
        assert!(summary.scan_running);
        assert!(summary.has_scan);
    }

    #[test]
    fn module_run_summary_does_not_use_workspace_count_for_running_tool() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_running_tool_for_test("triage:run");
        *app.findings_mut() = vec![Finding::new_semgrep(
            "demo.rule",
            "src/app.rs",
            1,
            None,
            Severity::High,
            "stored finding",
        )];

        let summary = module_run_summary(&app);

        assert_eq!(summary.findings, 1);
        assert_eq!(summary.findings_label, "findings unknown");
        assert_eq!(summary.status, ModuleRunStatusKind::Running);
    }

    #[test]
    fn module_run_summary_reports_abort_and_failed_status() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_scan_panel(Some(ScanPanelState {
            run_id: None,
            target: PathBuf::from("./demo"),
            stage: "scanning".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: true,
            error: None,
        }));

        assert_eq!(
            module_run_summary(&app).status,
            ModuleRunStatusKind::Aborting
        );

        if let Some(scan) = app.scan_mut() {
            scan.running = false;
            scan.abort_requested = false;
            scan.error = Some("boom".to_string());
        }

        assert_eq!(module_run_summary(&app).status, ModuleRunStatusKind::Failed);
    }

    #[test]
    fn module_run_live_activity_projects_display_row() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_live_activity_state(Some(LiveActivity::new(
            LiveActivityPhase::Thinking,
            "triage:run",
            "reviewing persisted findings",
        )));

        let model = module_run_live_activity(&app).expect("activity row");

        assert_eq!(model.phase_label, "thinking");
        assert_eq!(model.subject, "triage:run");
        assert_eq!(model.detail, "reviewing persisted findings");
    }
}
