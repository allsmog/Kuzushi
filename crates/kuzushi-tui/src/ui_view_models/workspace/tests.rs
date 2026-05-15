use super::*;
use kuzushi_core::V2Config;
use std::path::PathBuf;

#[test]
fn workspace_model_formats_missing_workspace_defaults() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = workspace_model(&app);

    assert_eq!(model.target_label, "none");
    assert_eq!(model.state_label, ".kuzushi/v2");
    assert_eq!(model.findings_db_label, ".kuzushi/v2/findings.sqlite3");
    assert_eq!(model.findings_label, "unknown");
    assert_eq!(model.last_export_label, "none");
    assert!(model.empty);
    assert_eq!(model.rollup_total, 0);
    assert!(model.rollup_rows.is_empty());
}

#[test]
fn workspace_model_projects_workspace_summary_and_rollup() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.workspace_view = crate::app::WorkspaceView {
        root: Some(PathBuf::from("/tmp/kuzushi-demo")),
        state_dir: Some(PathBuf::from("/tmp/kuzushi-demo/.kuzushi/v2")),
        findings_db: Some(PathBuf::from(
            "/tmp/kuzushi-demo/.kuzushi/v2/findings.sqlite3",
        )),
        findings_count: Some(3),
        last_export: Some(PathBuf::from("/tmp/findings.json")),
        status: "workspace ready".to_string(),
    };
    app.findings = vec![
        finding_with_severity(Severity::Critical),
        finding_with_severity(Severity::High),
        finding_with_severity(Severity::Low),
    ];

    let model = workspace_model(&app);

    assert_eq!(model.target_label, "./kuzushi-demo");
    assert_eq!(model.state_label, "./v2");
    assert_eq!(model.findings_db_label, "./findings.sqlite3");
    assert_eq!(model.findings_label, "3");
    assert_eq!(model.last_export_label, "./findings.json");
    assert!(!model.empty);
    assert_eq!(model.rollup_total, 3);
    assert_eq!(model.rollup_rows[0].count, 1);
    assert_eq!(model.rollup_rows[1].severity, Severity::High);
    assert_eq!(model.rollup_rows[2].count, 0);
    assert_eq!(model.rollup_rows[3].count, 1);
}

fn finding_with_severity(severity: Severity) -> Finding {
    Finding::new_semgrep("rule.demo", "src/lib.rs", 1, None, severity, "demo")
}
