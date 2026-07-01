use super::*;
use crate::ScanPanelState;
use kuzushi_core::V2Config;
use std::path::PathBuf;
use std::time::Instant;

#[test]
fn status_footer_model_reports_idle_shell_segments() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = status_footer_model(&app);

    // Routing + view only: target/ctx/model are the top cockpit strip's job,
    // so each session fact is stated once per screen.
    assert_eq!(model.left_segments, ["mode:shell", "modules"]);
    assert_eq!(model.right_segments, ["0 findings"]);
    assert!(!model.warning);
}

#[test]
fn status_footer_model_surfaces_ctrl_c_warning() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.ctrl_c_armed_at = Some(Instant::now());

    let model = status_footer_model(&app);

    assert!(model.warning);
    assert_eq!(model.right_segments[0], "Ctrl+C again to exit");
}

#[test]
fn malformed_context_snapshot_surfaces_in_the_cockpit_strip() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.context_view.status = "malformed context snapshot. Next: context build".to_string();

    // The bottom bar no longer carries ctx; the malformed signal must still
    // reach the operator through the top cockpit strip.
    let strip = crate::ui_view_models::context_strip_model(&app);
    assert!(strip
        .compact_segments()
        .contains(&"ctx:malformed".to_string()));
}

#[test]
fn status_footer_shows_scope_chip_when_program_scope_loaded() {
    // M2 §2.1: when `.kuzushi/scope.toml` is loaded, the footer carries a
    // `scope: on` chip so operators know recon and import calls will be
    // gated. Absence of scope keeps the footer compact.
    let mut app = ShellApp::new(V2Config::default(), None);
    let scope = kuzushi_core::ProgramScope::parse(
        r#"
        [in_scope]
        hosts = ["*.example.com"]
        "#,
    )
    .unwrap();
    app.program_scope = Some(scope);

    let model = status_footer_model(&app);

    assert!(
        model.left_segments.iter().any(|s| s == "scope: on"),
        "expected scope: on chip, got {:?}",
        model.left_segments
    );

    app.program_scope = None;
    let model = status_footer_model(&app);
    assert!(
        !model.left_segments.iter().any(|s| s.starts_with("scope:")),
        "no scope chip expected when scope is None, got {:?}",
        model.left_segments
    );
}

#[test]
fn status_footer_shows_active_project_scope_chip() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.active_scope = Some(crate::app::TargetCandidateScope {
        id: "submodule-libs-parser".to_string(),
        kind: kuzushi_core::NestedProjectKind::Submodule,
        rel_path: "libs/parser".to_string(),
    });

    let model = status_footer_model(&app);

    assert!(
        model
            .left_segments
            .iter()
            .any(|segment| segment == "project-scope:libs/parser"),
        "expected active project scope chip, got {:?}",
        model.left_segments
    );
}

#[test]
fn status_footer_model_prefers_active_scan_status() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.config.model = Some("openai:gpt-5.2".to_string());
    app.scan = Some(ScanPanelState {
        run_id: None,
        target: PathBuf::from("."),
        stage: "semgrep".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });

    let model = status_footer_model(&app);

    assert_eq!(
        model.left_segments,
        ["mode:run", "openai:gpt-5.2", "running: semgrep"]
    );
}

#[test]
fn status_footer_model_reflects_active_tool_model_override() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.config.model = Some("anthropic:claude-default".to_string());
    app.set_running_tool_for_test("triage:run");
    app.active_model_override = Some("openai:gpt-tool".to_string());

    let model = status_footer_model(&app);

    assert_eq!(
        model.left_segments,
        ["mode:run", "openai:gpt-tool (tool)", "triage:run: active"]
    );
}
