use super::*;
use kuzushi_core::V2Config;

#[test]
fn run_timeline_model_includes_active_scan_row() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());
    app.scan = Some(ScanPanelState {
        run_id: Some("r-08e1aa".to_string()),
        target: PathBuf::from("/tmp/demo"),
        stage: "complete".to_string(),
        findings_count: 11,
        running: false,
        abort_requested: false,
        error: None,
    });

    let model = run_timeline_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(
        model.rows[0],
        RunTimelineRow {
            run_id: "r-08e1aa".to_string(),
            status: "complete".to_string(),
            status_kind: PastRunStatus::Complete,
            findings: "11".to_string(),
            target: "/tmp/demo".to_string(),
        }
    );
}

#[test]
fn run_timeline_model_filters_active_scan_from_past_runs() {
    let temp = tempfile::tempdir().unwrap();
    let runs_root = temp.path().join(".kuzushi/runs");
    std::fs::create_dir_all(runs_root.join("r-2026-05-06T14-31")).unwrap();
    std::fs::write(
        runs_root.join("r-2026-05-06T14-31/run.json"),
        r#"{"status":"completed","findings":18,"target":"~/work/acme"}"#,
    )
    .unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());
    app.scan = Some(ScanPanelState {
        run_id: Some("r-2026-05-06T14-31".to_string()),
        target: temp.path().to_path_buf(),
        stage: "running".to_string(),
        findings_count: 3,
        running: true,
        abort_requested: false,
        error: None,
    });

    let model = run_timeline_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].run_id, "r-2026-0");
    assert_eq!(model.rows[0].status_kind, PastRunStatus::Running);
    assert_eq!(model.rows[0].findings, "3");
}
