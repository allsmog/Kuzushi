use super::*;
use crate::ui_view_models::ui_run_dir;
use kuzushi_core::{RunSummary, RunTargetGitMetadata, V2Config};
use std::path::{Path, PathBuf};

fn test_run_dir(root: &Path, run_id: &str) -> PathBuf {
    ui_run_dir(Some(root), run_id)
}

#[test]
fn run_timeline_model_includes_active_scan_row() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("r-08e1aa".to_string()),
        target: PathBuf::from("/tmp/demo"),
        stage: "complete".to_string(),
        findings_count: 11,
        running: false,
        abort_requested: false,
        error: None,
    }));
    app.hydrate_all_view_data_for_test();

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
fn run_timeline_model_does_not_show_zero_findings_while_scan_is_running() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("r-08e1aa".to_string()),
        target: PathBuf::from("/tmp/demo"),
        stage: "queued".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    app.hydrate_all_view_data_for_test();

    let model = run_timeline_model(&app, 20);

    assert_eq!(model.rows[0].cells[2], "—");
}

#[test]
fn run_timeline_model_filters_active_scan_from_past_runs() {
    let temp = tempfile::tempdir().unwrap();
    write_status_run(temp.path(), "r-2026-05-06T14-31", "completed", 18);

    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("r-2026-05-06T14-31".to_string()),
        target: temp.path().to_path_buf(),
        stage: "running".to_string(),
        findings_count: 3,
        running: true,
        abort_requested: false,
        error: None,
    }));
    app.hydrate_all_view_data_for_test();

    let model = run_timeline_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(
        model.rows[0].cells[0],
        crate::app::compact_run_reference("r-2026-05-06T14-31")
    );
    assert_eq!(model.rows[0].tone, PastRunStatus::Running);
    assert_eq!(model.rows[0].cells[2], "3");
    assert_eq!(model.rows[0].cells[3], "rev:unknown");
}

#[test]
fn run_timeline_model_surfaces_run_revision_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let summary =
        completed_summary("r-with-revision", 18).with_target_git(Some(RunTargetGitMetadata {
            sha: "abcdef1234567890".to_string(),
            branch: Some("main".to_string()),
            dirty: true,
        }));
    kuzushi_core::write_run_summary(temp.path(), &summary).unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.hydrate_all_view_data_for_test();

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
    write_status_run(temp.path(), "r-f-blocked", "blocked", 6);

    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.hydrate_all_view_data_for_test();

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
    assert_status_row(
        &model,
        "r-f-blocked",
        "blocked",
        PastRunStatus::Blocked,
        "6",
    );
}

#[test]
fn run_timeline_model_marks_missing_run_metadata_unknown() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = test_run_dir(temp.path(), "r-missing-run-json");
    std::fs::create_dir_all(&run_dir).unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.hydrate_all_view_data_for_test();

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
    app.set_target(Some(temp.path().to_path_buf()));
    app.hydrate_all_view_data_for_test();

    let model = run_timeline_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(
        model.rows[0].cells[0],
        crate::app::compact_run_reference("r-bad-run-json")
    );
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
    app.set_target(Some(temp.path().to_path_buf()));
    app.hydrate_all_view_data_for_test();

    let model = run_timeline_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(
        model.rows[0].cells[0],
        crate::app::compact_run_reference("r-array-run-json")
    );
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
    app.set_target(Some(temp.path().to_path_buf()));
    app.hydrate_all_view_data_for_test();

    let model = run_timeline_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(
        model.rows[0].cells[0],
        crate::app::compact_run_reference("r-unreadable-run-json")
    );
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
    app.set_target(Some(temp.path().to_path_buf()));
    app.hydrate_all_view_data_for_test();

    let model = run_timeline_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(
        model.rows[0].cells[0],
        crate::app::compact_run_reference("r-missing-run-json")
    );
    assert_eq!(model.rows[0].cells[1], "—");
    assert_eq!(model.rows[0].cells[2], "\u{2014}");
    assert_eq!(model.rows[0].cells[3], "rev:unknown");
    assert_eq!(model.rows[0].cells[4], "");
    assert_eq!(model.rows[0].tone, PastRunStatus::Unknown);
}

fn write_status_run(root: &Path, run_id: &str, status: &str, findings: u64) {
    let mut summary = completed_summary(run_id, findings);
    summary.status = status.to_string();
    kuzushi_core::write_run_summary(root, &summary).unwrap();
}

fn completed_summary(run_id: &str, findings: u64) -> RunSummary {
    RunSummary::running(run_id, "scan", Some("sast:scan".to_string()), "~/work/acme")
        .with_findings(Some(findings))
        .complete()
}

#[test]
fn timeline_run_reference_is_copyable_and_resolvable() {
    let temp = tempfile::tempdir().unwrap();
    let run_id = "scan-1783894713-68385f526477";
    write_status_run(temp.path(), run_id, "completed", 7);

    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.hydrate_all_view_data_for_test();

    let model = run_timeline_model(&app, 20);
    let displayed = model.rows[0].cells[0].as_str();

    assert!(!displayed.contains('…'));
    assert_eq!(
        crate::app::resolve_run_reference(displayed, [run_id]),
        crate::app::RunReferenceResolution::Resolved(run_id.to_string())
    );
}

fn assert_status_row(
    model: &RunTimelineModel,
    run_id: &str,
    status: &str,
    tone: PastRunStatus,
    findings: &str,
) {
    let reference = crate::app::compact_run_reference(run_id);
    let row = model
        .rows
        .iter()
        .find(|row| row.cells[0] == reference)
        .unwrap_or_else(|| panic!("missing row for {run_id}"));
    assert_eq!(row.cells[1], status);
    assert_eq!(row.cells[2], findings);
    assert_eq!(row.tone, tone);
}
