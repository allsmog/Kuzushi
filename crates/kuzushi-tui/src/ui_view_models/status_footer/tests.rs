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
