use super::*;
use crate::ScanPanelState;
use kuzushi_core::V2Config;
use std::path::PathBuf;
use std::time::Instant;

#[test]
fn status_footer_model_reports_idle_shell_segments() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = status_footer_model(&app);

    assert_eq!(
        model.left_segments,
        ["mode:shell", "target:none", "ctx:not built", "modules"]
    );
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
fn status_footer_model_reports_malformed_context_snapshot() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.context_view.status = "malformed context snapshot. Next: context build".to_string();

    let model = status_footer_model(&app);

    assert_eq!(
        model.left_segments,
        ["mode:shell", "target:none", "ctx:malformed", "modules"]
    );
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
fn status_footer_model_marks_cwd_target_with_warning_chip() {
    // M1 §1.3: when the active target equals the process cwd the footer
    // shows `target:cwd (.)` so the operator knows scope is implicit.
    let tmp = tempfile::tempdir().unwrap();
    let original_cwd = std::env::current_dir().ok();
    std::env::set_current_dir(tmp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(tmp.path().to_path_buf());

    let model = status_footer_model(&app);

    if let Some(cwd) = original_cwd {
        let _ = std::env::set_current_dir(cwd);
    }
    assert!(
        model.left_segments.iter().any(|s| s == "target:cwd (.)"),
        "expected target:cwd (.) chip, got {:?}",
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
