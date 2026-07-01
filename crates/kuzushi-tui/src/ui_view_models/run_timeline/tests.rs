use super::*;
use crate::ui_view_models::ui_run_dir;
use kuzushi_core::V2Config;

fn test_run_dir(root: &Path, run_id: &str) -> PathBuf {
    ui_run_dir(Some(root), run_id)
}

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
                "rev:unknown".to_string(),
                "/tmp/demo".to_string(),
            ],
            tone: PastRunStatus::Complete,
        }
    );
}

#[test]
fn run_timeline_model_filters_active_scan_from_past_runs() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = test_run_dir(temp.path(), "r-2026-05-06T14-31");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(
        run_dir.join(run_metadata_artifact_leaf()),
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
    assert_eq!(model.rows[0].cells[3], "rev:unknown");
}

#[test]
fn run_timeline_model_surfaces_run_revision_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = test_run_dir(temp.path(), "r-with-revision");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(
        run_dir.join(run_metadata_artifact_leaf()),
        r#"{"status":"completed","findings":18,"targetGit":{"sha":"abcdef1234567890","branch":"main","dirty":true},"target":"~/work/acme"}"#,
    )
    .unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());

    let model = run_timeline_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].cells[3], "rev:abcdef1*");
    assert_eq!(model.rows[0].cells[4], "~/work/acme");
}

#[test]
fn run_timeline_model_surfaces_malformed_run_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = test_run_dir(temp.path(), "r-bad-run-json");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(run_dir.join(run_metadata_artifact_leaf()), "{not-json").unwrap();
    std::fs::write(
        run_dir.join(LEGACY_RUN_SUMMARY_FILE),
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
    assert_eq!(model.rows[0].cells[3], "rev:unknown");
    assert_eq!(
        model.rows[0].cells[4],
        format!("malformed {}", run_metadata_artifact_leaf())
    );
    assert_eq!(model.rows[0].tone, PastRunStatus::Malformed);
}

#[test]
fn run_timeline_model_surfaces_non_object_run_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = test_run_dir(temp.path(), "r-array-run-json");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(run_dir.join(run_metadata_artifact_leaf()), "[]").unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());

    let model = run_timeline_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].cells[0], "r-array-run-json");
    assert_eq!(model.rows[0].cells[1], "malformed");
    assert_eq!(model.rows[0].cells[3], "rev:unknown");
    assert_eq!(
        model.rows[0].cells[4],
        format!("malformed {}", run_metadata_artifact_leaf())
    );
    assert_eq!(model.rows[0].tone, PastRunStatus::Malformed);
}

#[test]
fn run_timeline_model_surfaces_non_file_run_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = test_run_dir(temp.path(), "r-unreadable-run-json");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::create_dir(run_dir.join(run_metadata_artifact_leaf())).unwrap();
    std::fs::write(
        run_dir.join(LEGACY_RUN_SUMMARY_FILE),
        r#"{"status":"completed","findings":18,"target":"legacy"}"#,
    )
    .unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());

    let model = run_timeline_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].cells[0], "r-unre…n-json");
    assert_eq!(model.rows[0].cells[1], "malformed");
    assert_eq!(model.rows[0].cells[3], "rev:unknown");
    assert_eq!(
        model.rows[0].cells[4],
        format!("{} is not a file", run_metadata_artifact_leaf())
    );
    assert_eq!(model.rows[0].tone, PastRunStatus::Malformed);
}

#[test]
fn run_timeline_model_surfaces_non_file_summary_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = test_run_dir(temp.path(), "r-unreadable-summary-json");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::create_dir(run_dir.join(LEGACY_RUN_SUMMARY_FILE)).unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());

    let model = run_timeline_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].cells[0], "r-unre…y-json");
    assert_eq!(model.rows[0].cells[1], "malformed");
    assert_eq!(model.rows[0].cells[3], "rev:unknown");
    assert_eq!(
        model.rows[0].cells[4],
        format!("{LEGACY_RUN_SUMMARY_FILE} is not a file")
    );
    assert_eq!(model.rows[0].tone, PastRunStatus::Malformed);
}
