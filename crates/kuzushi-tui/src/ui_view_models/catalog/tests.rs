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
        Some("[!] target required; Enter opens picker · `target <path>` · `demo` offline")
    );
    assert_eq!(model.collapsed.scan_command, "target .; next");

    app.set_target(Some(PathBuf::from(".")));
    app.domain_mut().context_view_mut().exists = true;
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
fn catalog_default_action_hint_is_display_ready() {
    let app = ShellApp::new(V2Config::default(), None);
    let model = catalog_model(&app);
    let module = model.default_action.as_ref().expect("default action");

    let hint = catalog_default_action_hint(module, 80);

    assert!(hint.starts_with("Load Quick map —"));
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
    app.engagement.set_phase(kuzushi_core::WorkflowPhase::Hunt);

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
