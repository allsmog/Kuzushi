use super::*;

fn linked_reader(width: u16, height: u16) -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let mut app = large_job_reader(width, height);
    app.set_target(Some(root.path().into()));
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(crate::WorkbenchPage::Scan));
    let target = app.target_owned().unwrap();
    let origin = app.capture_linked_findings_origin(target, String::new());
    app.set_shell_view(ShellView::Campaign);
    app.router.campaign_mut().scan_study_origin = Some(origin);
    app.set_input_mode(crate::InputMode::Navigate);
    (root, app)
}

#[test]
fn linked_study_return_hints_match_actual_back_behavior_at_every_size() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let (root, mut app) = linked_reader(width, height);
        app.set_input("retained Unicode 東京 draft");
        let screen = draw(&app);
        assert!(screen.contains("Esc Scan"), "{width}x{height}: {screen}");
        assert_no_false_return(&screen);
        press(&mut app, KeyCode::Enter);
        assert!(app.router.campaign().job_detail);
        let screen = draw(&app);
        assert!(screen.contains("Esc jobs"), "{width}x{height}: {screen}");
        assert_no_false_return(&screen);
        press(&mut app, KeyCode::Esc);
        assert!(!app.router.campaign().job_detail);
        assert_eq!(app.shell_view(), ShellView::Campaign);
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.shell_view(), ShellView::Workbench);
        assert_eq!(
            app.router.workbench().page(),
            Some(crate::WorkbenchPage::Scan)
        );
        assert_eq!(app.input(), "retained Unicode 東京 draft");
        assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
    }
}

fn assert_no_false_return(screen: &str) {
    for hint in ["q list", "Esc compose", "Esc returns to prompt"] {
        assert!(!screen.contains(hint), "False return hint {hint}: {screen}");
    }
}

#[test]
fn linked_return_projection_yields_to_prompt_input_and_other_targets() {
    let (_root, mut app) = linked_reader(120, 36);
    assert!(crate::ui_view_models::linked_study_return_binding(&app).is_some());
    app.set_input_mode(crate::InputMode::Prompt);
    app.set_input("typing belongs to the composer");
    assert!(crate::ui_view_models::linked_study_return_binding(&app).is_none());
    assert!(draw(&app).contains("typing belongs to the composer"));
    app.set_input_mode(crate::InputMode::Navigate);
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().into()));
    assert!(crate::ui_view_models::linked_study_return_binding(&app).is_none());
}
