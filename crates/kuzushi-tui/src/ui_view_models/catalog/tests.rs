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
        Some("[!] no target selected; `scan .` uses the current directory")
    );
    assert_eq!(model.collapsed.scan_command, "scan .");

    app.target = Some(PathBuf::from("."));
    app.context_view.exists = true;
    let model = catalog_model(&app);
    assert!(model.collapsed.next_hint.contains("First finding"));
    assert_eq!(
        model.collapsed.target_warning,
        Some("[!] active target has no persisted findings yet")
    );
    assert_eq!(model.collapsed.scan_command, "scan");
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
