#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn umbrella_scan_reports_already_running_without_spawning_worker() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_scan_panel(Some(ScanPanelState {
            run_id: None,
            target: temp.path().to_path_buf(),
            stage: "running".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        }));

        let effects = app.reduce_scan_start(Some(temp.path().to_path_buf()), None);
        EffectRuntime::execute(&mut app, effects);

        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("scan already running")));
    }

    #[test]
    fn umbrella_scan_reports_invalid_target_before_worker_spawn() {
        let temp = tempfile::tempdir().unwrap();
        let file_target = temp.path().join("not-a-directory");
        std::fs::write(&file_target, "x").unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);

        let effects = app.reduce_scan_start(Some(file_target), None);
        EffectRuntime::execute(&mut app, effects);

        assert!(app.scan_is_none());
        assert!(app.log_lines().iter().any(|line| line.prefix == "error"));
    }

    #[test]
    fn guided_scan_with_target_opens_current_phase_picker_without_worker() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);

        let effects = app.open_guided_scan(Some(temp.path().to_path_buf()));

        assert!(matches!(
            &effects[..],
            [
                ShellEffect::ActivateTarget(TargetActivation { .. }),
                ShellEffect::FinalizeGuidedScanOpen
            ]
        ));

        EffectRuntime::execute(&mut app, effects);

        assert_eq!(app.shell_view(), ShellView::PlanningPicker);
        assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Map));
        assert!(app.target().is_some());
        assert!(app.scan_is_none());
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.prefix == "scan" && line.body.contains("guided workflow")));
    }

    #[test]
    fn guided_scan_uses_active_target_without_cwd_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

        let effects = app.open_guided_scan(None);

        assert!(matches!(
            &effects[..],
            [ShellEffect::FinalizeGuidedScanOpen]
        ));

        EffectRuntime::execute(&mut app, effects);

        assert_eq!(app.shell_view(), ShellView::PlanningPicker);
        assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Map));
        assert_eq!(app.target(), Some(workspace.root()));
        assert!(app.scan_is_none());
    }

    #[test]
    fn bare_guided_scan_without_target_refuses_to_use_cwd() {
        let mut app = ShellApp::new(V2Config::default(), None);

        let effects = app.open_guided_scan(None);

        assert!(effects.is_empty());

        assert_eq!(app.shell_view(), ShellView::Catalog);
        assert!(app.target().is_none());
        assert!(app.scan_is_none());
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.prefix == "scan" && line.body.contains("scan .")));
    }
}
