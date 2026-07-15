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

        assert!(app.log_lines().iter().any(|line| {
            line.body.contains("scan start blocked") && line.body.contains("then retry")
        }));
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
    fn guided_scan_with_fresh_target_opens_map_questions_without_worker() {
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

        assert_eq!(app.shell_view(), ShellView::Workbench);
        assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Map));
        assert!(app.guided_scan_question_model().is_some_and(|question| {
            question.header == "MAP · ROUTE" && question.options.iter().any(|option| option.other)
        }));
        assert!(app.target().is_some());
        assert!(app.scan_is_none());
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.prefix == "scan" && line.body.contains("guided scan opened")));
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

        assert_eq!(app.shell_view(), ShellView::Workbench);
        assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Map));
        assert_eq!(
            app.guided_scan_question_model()
                .map(|question| question.header),
            Some("MAP · ROUTE".to_string())
        );
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

    #[test]
    fn guided_scan_cannot_switch_target_while_tool_work_is_live() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(first.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        let prior_view = app.shell_view();
        app.set_running_tool_for_test("context:build");

        let effects = app.open_guided_scan(Some(second.path().to_path_buf()));

        assert!(effects.is_empty());
        assert_eq!(app.target(), Some(workspace.root()));
        assert_eq!(app.shell_view(), prior_view);
        assert!(app.log_lines().iter().any(|line| {
            line.prefix == "scan"
                && line.body.contains("scan start blocked")
                && line.body.contains("then retry")
        }));
    }

    #[test]
    fn prepared_scan_rechecks_all_live_job_slots_before_dispatch() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        let effects = app.prepare_scan_start_effect(ScanStartPreparation {
            target: Some(workspace.root().to_path_buf()),
            explicit_input: None,
        });
        assert!(matches!(effects.as_slice(), [ShellEffect::StartScan(_)]));

        let plan_ticket = app.jobs_mut().start(JobKind::Plan, "planner");
        EffectRuntime::execute(&mut app, effects);

        assert!(app.scan_is_none());
        assert!(!app.jobs().is_running(JobKind::Run));
        assert!(app.jobs().is_running(JobKind::Plan));
        assert!(app
            .log_lines()
            .iter()
            .any(|line| { line.prefix == "scan" && line.body.contains("scan start blocked") }));

        app.jobs_mut().finish(JobKind::Plan);
        plan_ticket.complete();
    }
}
