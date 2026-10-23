use super::*;

#[test]
fn context_shortcut_respects_input_ownership_and_modified_keys() {
    let (_root, mut app, _) = fixture();
    app.set_input_mode(InputMode::Prompt);
    app.set_input("draft");
    app.reduce_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
    assert_eq!(app.input(), "draftg");
    assert!(app.router.campaign().batch_scan_config.is_none());
    app.set_input_mode(InputMode::Navigate);
    app.reduce_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::ALT));
    assert!(app.router.campaign().batch_scan_config.is_none());
    app.reduce_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
    assert!(config(&app).context_generation.is_some());
}

#[test]
fn context_plan_from_node_flow_and_boundary_is_one_inactive_architecture_draft() {
    for selected in [0, 2, 3] {
        let (root, mut app, reference) = fixture();
        app.router.scene_mut().set_dfd_selection(selected, 4);
        let update = app.open_selected_dfd_context_study();
        assert!(update.effects.is_empty());
        let config = config(&app);
        let generation = config.context_generation.as_ref().unwrap();
        assert_eq!(
            generation.generation_tool.as_deref(),
            Some("threat-model:build")
        );
        assert_eq!(
            generation.context_input["sourcePaths"],
            json!([" app /source.rs", "src/a,b.rs"])
        );
        assert_eq!(
            generation.context_input["inheritedContextRef"],
            json!(reference)
        );
        assert!(generation.receipt.is_none());
        assert!(generation.generated.is_none());
        assert!(config.study.scan_input.is_none());
        assert!(config.dfd_origin.is_some());
        assert!(generation.is_scope_context() && generation.allows_model_choice());
        assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
        let lines =
            crate::ui_view_models::context_generation::generation_lines(&app, 120).join("\n");
        assert!(lines.contains("One full architecture draft"));
        assert!(lines.contains("\" app /source.rs\""));
        assert!(lines.contains("Dollar estimate unavailable"));
    }
}

#[test]
fn leaving_context_plan_restores_the_diagram_and_unsent_input() {
    let (_root, mut app, _) = fixture();
    app.router.scene_mut().toggle_dfd_focus();
    app.router.scene_mut().cycle_dfd_context_selection(1, 2);
    let scene = app.router.scene().clone();
    app.set_input("unsent context question");
    app.open_selected_dfd_context_study();
    assert_eq!(
        config(&app)
            .context_generation
            .as_ref()
            .unwrap()
            .context_input["sourcePaths"],
        json!(["src/a,b.rs"])
    );
    app.handle_context_generation_key(KeyCode::Esc);
    assert!(app.study_draft_recovery_open());
    app.study_recovery_input(KeyCode::Char('d'));
    assert!(app.router.campaign().batch_scan_config.is_none());
    assert_eq!(app.router.scene(), &scene);
    assert_eq!(app.input(), "unsent context question");
}

#[test]
fn context_plan_refuses_nested_work_and_keeps_parent_draft() {
    let (_root, mut app, _) = fixture();
    app.open_selected_dfd_context_study();
    let before = config(&app).clone();
    app.open_selected_dfd_context_study();
    assert_eq!(config(&app), &before);
}
