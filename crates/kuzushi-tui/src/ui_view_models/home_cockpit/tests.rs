use super::*;

#[test]
fn artifact_state_maps_home_rail_glyphs() {
    assert_eq!(
        artifact_state_from_text(r#"{"status":"completed"}"#).label,
        "recorded"
    );
    assert_eq!(
        artifact_state_from_text(r#"{"status":"skipped"}"#).label,
        "placeholder"
    );
    assert_eq!(
        artifact_state_from_text(r#"{"status":"failed"}"#).label,
        "failed"
    );
    assert_eq!(
        artifact_state_from_text(r#"{"status":"partial"}"#).label,
        "partial"
    );
    assert_eq!(
        artifact_state_from_text("No report was recorded for this run.").label,
        "placeholder"
    );
    assert_eq!(
        artifact_state_from_json_text("{not-json").label,
        "malformed"
    );
}

#[test]
fn home_artifact_row_shapes_display_cells() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = temp.path();
    std::fs::write(run_dir.join("context.json"), r#"{"status":"partial"}"#).unwrap();

    let row = home_artifact_row(run_dir, &HomeArtifactSpec::new("ctx", "context.json"));

    assert_eq!(
        row.cells,
        [
            "◆".to_string(),
            "ctx".to_string(),
            "partial".to_string(),
            run_dir.join("context.json").display().to_string(),
        ]
    );
}

#[test]
fn home_artifact_row_surfaces_malformed_json_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = temp.path();
    std::fs::write(run_dir.join("context.json"), "{not-json").unwrap();

    let row = home_artifact_row(run_dir, &HomeArtifactSpec::new("ctx", "context.json"));

    assert_eq!(
        row.cells,
        [
            "⚠".to_string(),
            "ctx".to_string(),
            "malformed".to_string(),
            run_dir.join("context.json").display().to_string(),
        ]
    );
}

#[test]
fn home_artifact_row_surfaces_unreadable_artifact_paths() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = temp.path();
    std::fs::create_dir(run_dir.join("context.json")).unwrap();

    let row = home_artifact_row(run_dir, &HomeArtifactSpec::new("ctx", "context.json"));

    assert_eq!(row.cells[0], "⚠");
    assert_eq!(row.cells[2], "malformed");
}

#[test]
fn home_artifact_row_keeps_markdown_reports_unstructured() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = temp.path();
    std::fs::write(run_dir.join("report.md"), "{not-json").unwrap();

    let row = home_artifact_row(run_dir, &HomeArtifactSpec::new("report", "report.md"));

    assert_eq!(row.cells[2], "recorded");
}

#[test]
fn home_cockpit_model_shapes_static_chrome_and_summary_rows() {
    let app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let model = home_cockpit_model(&app);

    assert_eq!(model.title, "HOME");
    assert_eq!(
        model
            .summary_rows
            .iter()
            .map(|row| row.cells[0].as_str())
            .collect::<Vec<_>>(),
        vec!["target", "latest run", "run status", "modules", "findings"]
    );
    assert_eq!(
        model.rail_legend,
        "rails: ✓ recorded → ○ placeholder ⚠ failed/malformed ■ missing ◆ partial"
    );
    assert_eq!(
        model.command_labels,
        [
            "modules",
            "recommend",
            "quickstart",
            "scan .",
            "findings",
            "runs",
        ]
    );
}

#[test]
fn home_cockpit_model_surfaces_invalid_latest_pointer() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join(".kuzushi/latest")).unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());

    let model = home_cockpit_model(&app);

    assert!(model
        .summary_rows
        .iter()
        .any(|row| { row.cells[0] == "latest run" && row.cells[1] == "invalid latest pointer" }));
    assert!(model
        .summary_rows
        .iter()
        .any(|row| { row.cells[0] == "run status" && row.cells[1] == "no run.json" }));
}

#[test]
fn home_cockpit_model_surfaces_blank_latest_pointer() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join(".kuzushi")).unwrap();
    std::fs::write(temp.path().join(".kuzushi/latest"), "\n").unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());

    let model = home_cockpit_model(&app);

    assert!(model
        .summary_rows
        .iter()
        .any(|row| { row.cells[0] == "latest run" && row.cells[1] == "invalid latest pointer" }));
}

#[test]
fn run_status_label_surfaces_malformed_run_json() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("run.json"), "{not-json").unwrap();

    assert_eq!(run_status_label(temp.path()), "malformed run.json");
}

#[test]
fn run_status_label_surfaces_unreadable_run_json() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("run.json")).unwrap();

    assert_eq!(run_status_label(temp.path()), "malformed run.json");
}

#[test]
fn home_cockpit_artifact_rail_includes_manifest() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = temp.path();
    std::fs::write(
        run_dir.join("artifacts.json"),
        r#"{"runId":"run-home","artifacts":[]}"#,
    )
    .unwrap();

    let rows = home_artifact_rows(run_dir);

    assert!(rows.iter().any(|row| {
        row.cells[1] == "manifest"
            && row.cells[2] == "recorded"
            && row.cells[3].ends_with("artifacts.json")
    }));
}
