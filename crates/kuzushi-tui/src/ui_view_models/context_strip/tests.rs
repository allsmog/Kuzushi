use super::*;
use crate::ScanPanelState;
use kuzushi_core::V2Config;
use std::path::PathBuf;

#[test]
fn context_strip_model_reports_idle_shell_state() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = context_strip_model(&app);

    assert_eq!(model.mode, "mode:shell");
    assert_eq!(model.target, "none");
    assert!(!model.context_present);
    assert_eq!(model.model, "unconfigured");
    assert_eq!(model.findings, "0 findings");
    assert_eq!(model.view, "modules");
    assert_eq!(model.cost, None);
    assert_eq!(
        model.compact_segments(),
        [
            "mode:shell",
            "target none",
            "ctx missing",
            "model unconfigured",
            "0 findings",
            "view modules"
        ]
    );
}

#[test]
fn context_strip_model_formats_target_model_context_and_cost() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(PathBuf::from("/tmp/acme"));
    app.context_view.exists = true;
    app.config.model = Some("openai:gpt-5.2".to_string());
    app.session_cost_usd = 0.42;

    let model = context_strip_model(&app);

    assert_eq!(model.target, "./acme");
    assert!(model.context_present);
    assert_eq!(model.model, "openai:gpt-5.2");
    assert_eq!(model.cost, Some("$0.42".to_string()));
    assert!(model
        .compact_segments()
        .contains(&"ctx ✓ present".to_string()));
}

#[test]
fn context_strip_model_reports_active_scan_stage() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.scan = Some(ScanPanelState {
        run_id: None,
        target: PathBuf::from("."),
        stage: "semgrep".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });

    let model = context_strip_model(&app);

    assert_eq!(model.mode, "mode:run");
    assert_eq!(
        model.stage,
        Some(ContextStripSegment {
            label: "stage",
            value: "⠿ searching".to_string()
        })
    );
}

#[test]
fn plain_context_strip_line_projects_status_and_module_count() {
    let strip = ContextStripModel {
        mode: "mode:shell".to_string(),
        target: "none".to_string(),
        context_present: false,
        model: "unconfigured".to_string(),
        findings: "0 findings".to_string(),
        view: "modules".to_string(),
        compact_activity: None,
        activity: None,
        run: None,
        stage: None,
        cost: None,
    };

    assert_eq!(
        plain_context_strip_line(&strip, 12, 80),
        "mode:shell | target:none | modules | 0 findings | 12 mods"
    );
    assert_eq!(plain_context_strip_line(&strip, 12, 10), "mode:sh...");
}
