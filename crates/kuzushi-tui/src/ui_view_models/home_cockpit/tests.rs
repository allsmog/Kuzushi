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
        "rails: ✓ recorded → ○ placeholder ⚠ failed ■ missing ◆ partial"
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
