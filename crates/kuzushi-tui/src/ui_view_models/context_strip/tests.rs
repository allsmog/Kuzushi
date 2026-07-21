use super::*;
use crate::ScanPanelState;
use kuzushi_core::V2Config;
use std::path::PathBuf;

#[test]
fn context_strip_model_reports_idle_shell_state() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = context_strip_model(&app);

    assert_eq!(model.mode, "shell route");
    assert_eq!(model.target, "none");
    assert!(!model.context_present);
    assert_eq!(model.context_state, "missing");
    assert_eq!(model.model, "unconfigured");
    assert_eq!(model.findings, "0 findings");
    assert_eq!(model.view, "capabilities");
    assert_eq!(model.phase, None);
    assert_eq!(model.cost, Some("$0.00 (no model calls)".to_string()));
    assert_eq!(
        model.compact_segments(),
        [
            "shell route",
            "view:capabilities",
            "target:none",
            "model:unconfigured",
            "context not built",
            "cost:$0.00 (no model calls)"
        ]
    );
}

#[test]
fn context_strip_model_formats_target_model_context_and_cost() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(PathBuf::from("/tmp/acme")));
    app.domain_mut().context_view_mut().exists = true;
    app.config_mut().model = Some("openai:gpt-5.2".to_string());
    app.session_mut().mark_session_api_key_ready("openai");
    app.session_mut().set_session_cost_usd_for_test(0.42);

    let model = context_strip_model(&app);

    assert_eq!(model.target, "./acme");
    assert!(model.context_present);
    assert_eq!(model.context_state, "present");
    assert_eq!(model.model, "openai:gpt-5.2");
    assert_eq!(model.phase.as_deref(), Some("Map 1/5"));
    assert_eq!(model.cost, Some("$0.42".to_string()));
    assert!(model
        .compact_segments()
        .contains(&"context ready".to_string()));
}

#[test]
fn context_strip_qualifies_configured_models_with_missing_auth() {
    assert_eq!(
        qualified_model_segment(Some("openai:gpt-5.5"), false),
        "openai:gpt-5.5 [auth missing]"
    );
    assert_eq!(
        qualified_model_segment(Some("openai:gpt-5.5"), true),
        "openai:gpt-5.5"
    );
}

#[test]
fn context_strip_model_reports_malformed_context_snapshot() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut().context_view_mut().status =
        "malformed context snapshot. Next: context build".to_string();

    let model = context_strip_model(&app);

    assert!(!model.context_present);
    assert_eq!(model.context_state, "malformed");
    assert!(model
        .compact_segments()
        .contains(&"context malformed".to_string()));
}

#[test]
fn context_strip_model_reports_active_scan_stage() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_scan_panel(Some(ScanPanelState {
        run_id: None,
        target: PathBuf::from("."),
        stage: "semgrep".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));

    let model = context_strip_model(&app);

    assert_eq!(model.mode, "run route");
    assert_eq!(
        model.stage,
        Some(ContextStripSegment {
            label: "stage",
            value: "⠿ searching".to_string()
        })
    );
}
