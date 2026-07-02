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
        Some("[!] no target selected; run `target .`, then `next`")
    );
    assert_eq!(model.collapsed.scan_command, "target .; next");

    app.target = Some(PathBuf::from("."));
    app.context_view.exists = true;
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
    app.context_view.status = "malformed context snapshot. Next: context build".to_string();

    let model = catalog_model(&app);

    assert_eq!(
        model.collapsed.next_hint,
        "Context snapshot is malformed; rerun `context build` before scanning."
    );
}

#[test]
fn catalog_collapsed_model_prioritizes_critical_alias_hint() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.context_view.exists = true;
    app.findings = vec![
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
fn catalog_collapsed_layout_uses_width_and_expand_toggle() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let model = catalog_model(&app);
    assert!(catalog_uses_collapsed_layout(&model, 80));
    assert!(!catalog_uses_collapsed_layout(&model, 120));

    app.catalog_expanded = true;
    let model = catalog_model(&app);
    assert!(!catalog_uses_collapsed_layout(&model, 80));
}

#[test]
fn catalog_default_action_hint_is_display_ready() {
    let app = ShellApp::new(V2Config::default(), None);
    let model = catalog_model(&app);
    let module = model.default_action.as_ref().expect("default action");

    let hint = catalog_default_action_hint(module, 80);

    assert!(hint.starts_with("Run sast —"));
    assert!(hint.len() <= 80);
}

#[test]
fn catalog_module_rows_shape_display_cells() {
    let app = ShellApp::new(V2Config::default(), None);
    let model = catalog_model(&app);
    let row = model
        .groups
        .iter()
        .flat_map(|group| group.rows.iter())
        .find(|row| row.id == "sast")
        .expect("sast row");

    assert_eq!(row.cells[0], "sast");
    assert!(!row.cells[1].is_empty());
}
