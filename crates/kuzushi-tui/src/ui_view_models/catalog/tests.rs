use super::*;
use kuzushi_core::{Finding, Severity, V2Config};
use std::path::PathBuf;

#[test]
fn catalog_collapsed_model_steers_context_then_findings() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let model = catalog_model(&app);
    assert!(model.collapsed.next_hint.contains("context build"));
    assert_eq!(
        model.collapsed.target_warning,
        Some("[!] target required · `target <path>` · `demo` offline")
    );
    assert_eq!(model.collapsed.scan_command, "target .; next");

    app.set_target(Some(PathBuf::from(".")));
    app.domain_mut().context_view_mut().exists = true;
    app.domain_mut().context_view_mut().freshness =
        Some(kuzushi_core::context::ContextSnapshotFreshness::Current);
    let model = catalog_model(&app);
    assert!(model.collapsed.next_hint.contains("First finding"));
    assert_eq!(
        model.collapsed.target_warning,
        Some("[!] active target has no persisted findings yet")
    );
    assert_eq!(model.collapsed.scan_command, "next");
}

#[test]
fn catalog_collapsed_model_surfaces_malformed_context_snapshot() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut().context_view_mut().status =
        "malformed context snapshot. Next: context build".to_string();

    let model = catalog_model(&app);

    assert_eq!(
        model.collapsed.next_hint,
        "Context snapshot is malformed; rerun `context build` before scanning."
    );
}

#[test]
fn catalog_collapsed_model_prioritizes_critical_alias_hint() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut().context_view_mut().exists = true;
    app.domain_mut().context_view_mut().freshness =
        Some(kuzushi_core::context::ContextSnapshotFreshness::Current);
    *app.findings_mut() = vec![
        Finding::new_semgrep("demo.medium", "src/a.rs", 1, None, Severity::Medium, "x"),
        Finding::new_semgrep(
            "demo.critical",
            "src/b.rs",
            2,
            None,
            Severity::Critical,
            "y",
        ),
    ];

    let model = catalog_model(&app);

    assert!(model.collapsed.next_hint.contains("open F-"));
    assert!(model.collapsed.scan_hint.is_none());
}

#[test]
fn capability_catalog_never_replaces_actions_with_a_bland_compact_state() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let model = catalog_model(&app);
    assert!(!catalog_uses_collapsed_layout(&model, 80));
    assert!(!catalog_uses_collapsed_layout(&model, 120));

    app.router.catalog_mut().expand();
    let model = catalog_model(&app);
    assert!(!catalog_uses_collapsed_layout(&model, 80));
}

#[test]
fn catalog_selected_action_hint_is_display_ready() {
    let app = ShellApp::new(V2Config::default(), None);
    let model = catalog_model(&app);
    let module = model.selected_action.as_ref().expect("selected action");

    let hint = catalog_selected_action_hint(module, 80);

    assert!(hint.starts_with("Load Quick map:"));
    assert!(hint.len() <= 80);
}

#[test]
fn catalog_capability_rows_shape_display_cells_and_commands() {
    let app = ShellApp::new(V2Config::default(), None);
    let model = catalog_model(&app);
    let row = model
        .groups
        .iter()
        .flat_map(|group| group.rows.iter())
        .find(|row| row.id == "quick-map")
        .expect("quick map row");

    assert_eq!(row.cells[0], "Quick map");
    assert_eq!(row.command, "next");
    assert!(!row.cells[1].is_empty());
}

#[test]
fn selected_action_hint_follows_the_visible_cursor_without_changing_the_draft() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(PathBuf::from(".")));
    app.set_input("an unfinished operator draft".to_string());
    app.move_catalog_cursor(1);

    let model = catalog_model(&app);
    let selected = model.selected_action.unwrap();
    assert_eq!(selected.id, "deep-map");
    assert_eq!(selected.command, app.catalog_cursor_command().unwrap());
    assert!(catalog_selected_action_hint(&selected, 120).starts_with("Load Deep threat map:"));
    assert_eq!(selected.readiness.label, "MODEL REQUIRED");
    assert_eq!(app.input(), "an unfinished operator draft");
}

#[test]
fn catalog_model_requirement_uses_the_same_stored_options_as_dispatch() {
    use kuzushi_core::{OptionScope, OptionTarget};
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(PathBuf::from(".")));
    app.move_catalog_cursor(1);
    app.option_store_mut().set_value(
        OptionScope::Session,
        OptionTarget::Tool("threat-model:build".to_string()),
        "pipeline",
        serde_json::json!("deterministic"),
    );

    let model = catalog_model(&app);
    assert_eq!(
        model.selected_action.unwrap().readiness.label,
        "REVIEW INPUTS"
    );
    assert!(app.config().model.is_none());
}

#[test]
fn catalog_readiness_never_turns_a_selected_model_into_execution_authority() {
    let mut config = V2Config::default();
    config.model = Some("openai-codex:gpt-5.5".into());
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(PathBuf::from(".")));
    app.move_catalog_cursor(1);

    let selected = catalog_model(&app).selected_action.unwrap();
    assert_eq!(selected.readiness.label, "REVIEW INPUTS");
    assert!(selected
        .readiness
        .next
        .contains("options threat-model:build"));
}

#[test]
fn catalog_reports_incompatible_model_auth_configuration_without_changing_it() {
    let mut config = V2Config::default();
    config.model = Some("other:fixture".into());
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(PathBuf::from(".")));
    app.move_catalog_cursor(1);

    let selected = catalog_model(&app).selected_action.unwrap();
    assert_eq!(selected.readiness.label, "RUNTIME CONFIG");
    assert!(selected.readiness.next.contains("doctor"));
    assert_eq!(app.config().model.as_deref(), Some("other:fixture"));
}

#[test]
fn catalog_runtime_free_input_skips_invalid_model_auth_configuration() {
    use kuzushi_core::{OptionScope, OptionTarget};
    let mut config = V2Config::default();
    config.model = Some("other:fixture".into());
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(PathBuf::from(".")));
    app.move_catalog_cursor(1);
    app.option_store_mut().set_value(
        OptionScope::Session,
        OptionTarget::Tool("threat-model:build".into()),
        "pipeline",
        serde_json::json!("deterministic"),
    );

    assert_eq!(
        catalog_model(&app).selected_action.unwrap().readiness.label,
        "REVIEW INPUTS"
    );
    assert_eq!(app.config().model.as_deref(), Some("other:fixture"));
}

#[test]
fn catalog_reports_the_same_credential_env_mismatch_as_runtime_policy() {
    let mut config = V2Config::default();
    config.model = Some("openai-codex:fixture".into());
    config.runtime.api_key_env = "ANTHROPIC_API_KEY".into();
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(PathBuf::from(".")));
    app.move_catalog_cursor(1);

    assert_eq!(
        catalog_model(&app).selected_action.unwrap().readiness.label,
        "RUNTIME CONFIG"
    );
    assert_eq!(app.config().runtime.api_key_env, "ANTHROPIC_API_KEY");
    assert!(
        kuzushi_core::runtime::bind_model_auth("openai-codex:fixture", "ANTHROPIC_API_KEY")
            .is_err()
    );
}

#[test]
fn targetless_catalog_explains_the_actual_enter_action() {
    let app = ShellApp::new(V2Config::default(), None);
    let selected = catalog_model(&app).selected_action.unwrap();
    assert_eq!(selected.readiness.label, "TARGET REQUIRED");
    assert_eq!(
        selected.readiness.next,
        "target <path> selects a repository"
    );
    assert!(catalog_model(&app)
        .input_hint
        .contains("Enter opens the target picker"));
}

#[test]
fn catalog_picker_load_control_is_visible_only_while_it_owns_input() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(PathBuf::from(".")));
    app.set_shell_view(crate::ShellView::Catalog);
    let bindings = crate::ui_view_models::footer_keybindings(&app);
    assert!(bindings
        .iter()
        .any(|binding| binding.key == "Enter" && binding.label == "load"));
    assert_eq!(
        bindings
            .iter()
            .filter(|binding| binding.key == "Enter")
            .count(),
        1
    );

    app.set_input("unfinished draft".to_string());
    let bindings = crate::ui_view_models::footer_keybindings(&app);
    assert!(!bindings
        .iter()
        .any(|binding| binding.key == "Enter" && binding.label == "load"));
    assert_eq!(app.input(), "unfinished draft");
}

#[test]
fn catalog_targetless_footer_names_the_target_picker() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(crate::ShellView::Catalog);
    let bindings = crate::ui_view_models::footer_keybindings(&app);
    let enter = bindings
        .iter()
        .filter(|binding| binding.key == "Enter")
        .collect::<Vec<_>>();
    assert_eq!(enter.len(), 1);
    assert_eq!(enter[0].label, "target picker");
    assert!(app.target().is_none());
}

#[test]
fn catalog_preserves_an_invalid_model_and_an_explicit_tool_override() {
    use kuzushi_core::{OptionScope, OptionTarget};
    let mut config = V2Config::default();
    config.model = Some("invalid-model".into());
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(PathBuf::from(".")));
    app.move_catalog_cursor(1);
    assert_eq!(
        catalog_model(&app).selected_action.unwrap().readiness.label,
        "MODEL CONFIG"
    );
    app.option_store_mut().set_value(
        OptionScope::Session,
        OptionTarget::Tool("threat-model:build".to_string()),
        "model",
        serde_json::json!("openai-codex:gpt-5.5"),
    );
    assert_eq!(
        catalog_model(&app).selected_action.unwrap().readiness.label,
        "REVIEW INPUTS"
    );
    assert_eq!(app.config().model.as_deref(), Some("invalid-model"));
}

#[test]
fn every_registered_module_has_an_explicit_product_disposition() {
    let app = ShellApp::new(V2Config::default(), None);
    let unclassified = app
        .registry()
        .all_modules()
        .filter(|module| capability_disposition(&module.metadata().id).is_none())
        .map(|module| module.metadata().id.clone())
        .collect::<Vec<_>>();

    assert!(
        unclassified.is_empty(),
        "unclassified modules: {unclassified:?}"
    );
}

#[test]
fn expert_toggle_keeps_default_surface_small_and_reveals_engines() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(PathBuf::from(".")));
    app.engagement.set_phase(kuzushi_core::WorkflowPhase::Scan);

    let default_model = catalog_model(&app);
    assert_eq!(default_model.module_count, 3);
    assert!(default_model
        .groups
        .iter()
        .all(|group| group.category == "CURRENT"));

    app.router.catalog_mut().expand();
    let expert_model = catalog_model(&app);
    assert!(expert_model.module_count > default_model.module_count);
    assert!(expert_model
        .groups
        .iter()
        .any(|group| group.category == "EXPERT"));
}

#[test]
fn registered_internal_or_labs_tools_are_not_guided_capability_actions() {
    let app = ShellApp::new(V2Config::default(), None);
    for tool in ["fuzz:status", "carlini-threat-hunt:run"] {
        assert!(app.registry().resolve_tool(tool).is_some());
        let spec = CapabilityActionSpec {
            id: "fixture",
            label: "Fixture",
            description: "visibility fixture",
            command: "",
            category: "EXPERT",
            required_tool: Some(tool),
            required_visible_module: None,
        };
        assert!(!spec.available(&app));
    }
}
