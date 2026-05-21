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
            cells: [
                "r-08e1aa".to_string(),
                "complete".to_string(),
                "11".to_string(),
                "/tmp/demo".to_string(),
            ],
            tone: PastRunStatus::Complete,
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
    assert_eq!(model.rows[0].cells[0], "r-2026…T14-31");
    assert_eq!(model.rows[0].tone, PastRunStatus::Running);
    assert_eq!(model.rows[0].cells[2], "3");
}

#[test]
fn run_timeline_model_surfaces_malformed_run_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let runs_root = temp.path().join(".kuzushi/runs");
    std::fs::create_dir_all(runs_root.join("r-bad-run-json")).unwrap();
    std::fs::write(runs_root.join("r-bad-run-json/run.json"), "{not-json").unwrap();
    std::fs::write(
        runs_root.join("r-bad-run-json/summary.json"),
        r#"{"status":"completed","findings":18,"target":"legacy"}"#,
    )
    .unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());

    let model = run_timeline_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].cells[0], "r-bad-run-json");
    assert_eq!(model.rows[0].cells[1], "malformed");
    assert_eq!(model.rows[0].cells[2], "\u{2014}");
    assert_eq!(model.rows[0].cells[3], "malformed run.json");
    assert_eq!(model.rows[0].tone, PastRunStatus::Malformed);
}

#[test]
fn run_timeline_model_surfaces_unreadable_run_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let runs_root = temp.path().join(".kuzushi/runs");
    let run_dir = runs_root.join("r-unreadable-run-json");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::create_dir(run_dir.join("run.json")).unwrap();
    std::fs::write(
        run_dir.join("summary.json"),
        r#"{"status":"completed","findings":18,"target":"legacy"}"#,
    )
    .unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());

    let model = run_timeline_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].cells[0], "r-unre…n-json");
    assert_eq!(model.rows[0].cells[1], "malformed");
    assert_eq!(model.rows[0].cells[3], "malformed run.json");
    assert_eq!(model.rows[0].tone, PastRunStatus::Malformed);
}

#[test]
fn run_timeline_model_surfaces_unreadable_summary_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let runs_root = temp.path().join(".kuzushi/runs");
    let run_dir = runs_root.join("r-unreadable-summary-json");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::create_dir(run_dir.join("summary.json")).unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());

    let model = run_timeline_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].cells[0], "r-unre…y-json");
    assert_eq!(model.rows[0].cells[1], "malformed");
    assert_eq!(model.rows[0].cells[3], "malformed summary.json");
    assert_eq!(model.rows[0].tone, PastRunStatus::Malformed);
}
