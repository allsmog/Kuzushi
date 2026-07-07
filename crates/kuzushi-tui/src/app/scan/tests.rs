#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn umbrella_scan_reports_already_running_without_spawning_worker() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.scan = Some(ScanPanelState {
            run_id: None,
            target: temp.path().to_path_buf(),
            stage: "running".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        });

        app.start_umbrella_sast_scan(Some(temp.path().to_path_buf()));

        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("scan already running")));
    }

    #[test]
    fn umbrella_scan_reports_invalid_target_before_worker_spawn() {
        let temp = tempfile::tempdir().unwrap();
        let file_target = temp.path().join("not-a-directory");
        std::fs::write(&file_target, "x").unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);

        app.start_umbrella_sast_scan(Some(file_target));

        assert!(app.scan.is_none());
        assert!(app.log.iter().any(|line| line.prefix == "error"));
    }

    #[test]
    fn guided_scan_with_target_opens_current_phase_picker_without_worker() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);

        app.open_guided_scan(Some(temp.path().to_path_buf()));

        assert_eq!(app.shell_view, ShellView::PlanningPicker);
        assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Map));
        assert!(app.target.is_some());
        assert!(app.scan.is_none());
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "scan" && line.body.contains("guided workflow")));
    }

    #[test]
    fn guided_scan_uses_active_target_without_cwd_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

        app.open_guided_scan(None);

        assert_eq!(app.shell_view, ShellView::PlanningPicker);
        assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Map));
        assert_eq!(app.target.as_deref(), Some(workspace.root()));
        assert!(app.scan.is_none());
    }

    #[test]
    fn bare_guided_scan_without_target_refuses_to_use_cwd() {
        let mut app = ShellApp::new(V2Config::default(), None);

        app.open_guided_scan(None);

        assert_eq!(app.shell_view, ShellView::Catalog);
        assert!(app.target.is_none());
        assert!(app.scan.is_none());
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "scan" && line.body.contains("scan .")));
    }
}
