use super::*;
use kuzushi_core::{Severity, V2Config};
use std::path::PathBuf;

#[test]
fn findings_db_relative_path_uses_core_workspace_path() {
    assert_eq!(
        findings_db_relative_path(),
        kuzushi_core::workspace::workspace_findings_db_path("")
            .display()
            .to_string()
    );
}

#[test]
fn workspace_state_relative_path_uses_core_workspace_path() {
    assert_eq!(
        workspace_state_relative_path(),
        kuzushi_core::workspace::workspace_state_dir("")
            .display()
            .to_string()
    );
}

#[test]
fn workspace_model_formats_missing_workspace_defaults() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = workspace_model(&app);

    assert_eq!(model.target_label, "none");
    assert_eq!(model.state_label, workspace_state_relative_path());
    assert_eq!(model.findings_db_label, findings_db_relative_path());
    assert_eq!(model.findings_label, "none yet (run scan first)");
    assert_eq!(model.last_export_label, "none");
    assert!(model.empty);
    assert_eq!(model.rollup_total, 0);
    assert!(model.rollup_rows.is_empty());
}

#[test]
fn workspace_model_projects_workspace_summary_and_rollup() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut()
        .set_workspace_view(crate::app::WorkspaceView {
            root: Some(PathBuf::from("/tmp/kuzushi-demo")),
            state_dir: Some(PathBuf::from("/tmp/kuzushi-demo/.kuzushi/v2")),
            findings_db: Some(PathBuf::from(
                "/tmp/kuzushi-demo/.kuzushi/v2/findings.sqlite3",
            )),
            findings_count: Some(3),
            last_export: Some(PathBuf::from("/tmp/findings.json")),
            status: "workspace ready".to_string(),
        });
    *app.findings_mut() = vec![
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
    assert_eq!(model.rollup_rows[1].severity_tone, SeverityTone::High);
    assert_eq!(model.rollup_rows[2].count, 0);
    assert_eq!(model.rollup_rows[3].count, 1);
}

#[test]
fn plain_workspace_model_projects_missing_workspace_rows() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = plain_workspace_model(&app);

    assert_eq!(model.title, "WORKSPACE");
    assert!(model.summary_rows.contains(&"target: none".to_string()));
    assert!(model
        .summary_rows
        .contains(&format!("findings db: {}", findings_db_relative_path())));
    assert!(model.empty_rows.is_empty());
    assert_eq!(
        model.next_hint,
        "Next: workspace status, workspace scope init, workspace export findings <path> [format] [--completeness open|complete] [--allow-empty]"
    );
}

#[test]
fn plain_workspace_model_projects_active_workspace_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut()
        .set_workspace_view(crate::app::WorkspaceView {
            root: Some(PathBuf::from("/tmp/kuzushi-demo")),
            state_dir: Some(PathBuf::from("/tmp/kuzushi-demo/.kuzushi/v2")),
            findings_db: Some(PathBuf::from(
                "/tmp/kuzushi-demo/.kuzushi/v2/findings.sqlite3",
            )),
            findings_count: Some(3),
            last_export: Some(PathBuf::from("/tmp/findings.json")),
            status: "workspace ready".to_string(),
        });

    let model = plain_workspace_model(&app);

    assert!(model
        .summary_rows
        .contains(&"status: workspace ready".to_string()));
    assert!(model
        .summary_rows
        .contains(&"target: ./kuzushi-demo".to_string()));
    assert!(model.summary_rows.contains(&"findings: 3".to_string()));
    assert!(model.empty_rows.is_empty());
}

fn finding_with_severity(severity: Severity) -> Finding {
    Finding::new_semgrep("rule.demo", "src/lib.rs", 1, None, severity, "demo")
}
