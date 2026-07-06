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
fn run_timeline_model_preserves_persisted_terminal_statuses() {
    let temp = tempfile::tempdir().unwrap();
    write_status_run(temp.path(), "r-a-partial", "partial", 1);
    write_status_run(temp.path(), "r-b-interrupt", "interrupted", 2);
    write_status_run(temp.path(), "r-c-failed", "failed", 3);
    write_status_run(temp.path(), "r-d-skipped", "skipped", 4);
    write_status_run(temp.path(), "r-e-paused", "paused", 5);

    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());

    let model = run_timeline_model(&app, 20);

    assert_status_row(
        &model,
        "r-a-partial",
        "partial",
        PastRunStatus::Partial,
        "1",
    );
    assert_status_row(
        &model,
        "r-b-interrupt",
        "interrupted",
        PastRunStatus::Interrupted,
        "2",
    );
    assert_status_row(&model, "r-c-failed", "failed", PastRunStatus::Failed, "3");
    assert_status_row(
        &model,
        "r-d-skipped",
        "skipped",
        PastRunStatus::Skipped,
        "4",
    );
    assert_status_row(&model, "r-e-paused", "paused", PastRunStatus::Paused, "5");
}

#[test]
fn run_timeline_model_marks_missing_run_metadata_unknown() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = test_run_dir(temp.path(), "r-missing-run-json");
    std::fs::create_dir_all(&run_dir).unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());

    let model = run_timeline_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].cells[1], "—");
    assert_eq!(model.rows[0].cells[2], "\u{2014}");
    assert_eq!(model.rows[0].cells[4], "");
}

#[test]
fn run_timeline_model_surfaces_malformed_run_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = test_run_dir(temp.path(), "r-bad-run-json");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(run_dir.join(run_metadata_artifact_leaf()), "{not-json").unwrap();

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
fn run_timeline_model_surfaces_missing_run_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = test_run_dir(temp.path(), "r-missing-run-json");
    std::fs::create_dir_all(&run_dir).unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());

    let model = run_timeline_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].cells[0], "r-miss…n-json");
    assert_eq!(model.rows[0].cells[1], "—");
    assert_eq!(model.rows[0].cells[2], "\u{2014}");
    assert_eq!(model.rows[0].cells[3], "rev:unknown");
    assert_eq!(model.rows[0].cells[4], "");
    assert_eq!(model.rows[0].tone, PastRunStatus::Unknown);
}

fn write_status_run(root: &Path, run_id: &str, status: &str, findings: u64) {
    let run_dir = test_run_dir(root, run_id);
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(
        run_dir.join(run_metadata_artifact_leaf()),
        format!(r#"{{"status":"{status}","findings":{findings},"target":"~/work/acme"}}"#),
    )
    .unwrap();
}

fn assert_status_row(
    model: &RunTimelineModel,
    run_id: &str,
    status: &str,
    tone: PastRunStatus,
    findings: &str,
) {
    let row = model
        .rows
        .iter()
        .find(|row| row.cells[0] == run_id)
        .unwrap_or_else(|| panic!("missing row for {run_id}"));
    assert_eq!(row.cells[1], status);
    assert_eq!(row.cells[2], findings);
    assert_eq!(row.tone, tone);
}
