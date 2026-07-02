use super::*;

fn create_invalid_latest_pointer(root: &std::path::Path) {
    std::fs::create_dir_all(ui_latest_run_path(Some(root))).unwrap();
}

fn write_blank_latest_pointer(root: &std::path::Path) {
    let latest_path = ui_latest_run_path(Some(root));
    std::fs::create_dir_all(latest_path.parent().unwrap()).unwrap();
    std::fs::write(latest_path, "\n").unwrap();
}

fn finding(rule: &str, severity: kuzushi_core::Severity, line: u32) -> Finding {
    Finding::new_tool("semgrep", rule, "src/lib.rs", line, None, severity, rule)
}

fn reviewed(mut finding: Finding) -> Finding {
    finding.triage = Some(kuzushi_core::TriageOutcome {
        verdict: kuzushi_core::TriageVerdict::TruePositive,
        confidence: 0.9,
        rationale: "reviewed".to_string(),
        cost_usd: 0.0,
    });
    finding
}

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

    let row = home_artifact_row(
        run_dir,
        RunArtifactSpec {
            label: "context snapshot",
            leaf: "context.json",
            kind: "json",
        },
    );

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

    let row = home_artifact_row(
        run_dir,
        RunArtifactSpec {
            label: "context snapshot",
            leaf: "context.json",
            kind: "json",
        },
    );

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
fn home_artifact_row_surfaces_non_file_artifact_paths() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = temp.path();
    std::fs::create_dir(run_dir.join("context.json")).unwrap();

    let row = home_artifact_row(
        run_dir,
        RunArtifactSpec {
            label: "context snapshot",
            leaf: "context.json",
            kind: "json",
        },
    );

    assert_eq!(row.cells[0], "⚠");
    assert_eq!(row.cells[2], "not a file");
}

#[test]
fn home_artifact_row_keeps_markdown_reports_unstructured() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = temp.path();
    std::fs::write(run_dir.join("report.md"), "{not-json").unwrap();

    let row = home_artifact_row(
        run_dir,
        RunArtifactSpec {
            label: "report",
            leaf: "report.md",
            kind: "markdown",
        },
    );

    assert_eq!(row.cells[2], "recorded");
}

#[test]
fn home_cockpit_model_shapes_static_chrome_and_cards() {
    let app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let model = home_cockpit_model(&app);

    assert_eq!(model.title, "HOME");
    assert_eq!(
        model.command_labels,
        [
            "target .",
            "options sast:scan",
            "tasks",
            "next",
            "quickstart",
            "Ctrl+G",
        ]
    );
    assert!(!model.command_labels.contains(&"scan ."));
    assert!(model.next_card.action.contains("guided workflow"));
    assert!(model.next_card.mechanics.contains("target ."));
    assert!(model.next_card.mechanics.contains("next"));
    assert!(!model.next_card.mechanics.contains("scan ."));
    assert_eq!(model.findings_card.total, 0);
    assert_eq!(model.run_card.recorded, 0);
    assert_eq!(model.run_card.total, 10);
    assert!(model.top_risks.is_empty());
    assert!(model.workspace_line.contains("target none"));
}

#[test]
fn active_home_commands_offer_one_guided_workflow_entrypoint() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());

    let model = home_cockpit_model(&app);

    assert_eq!(
        model.command_labels,
        [
            "next",
            "findings",
            "options sast:scan",
            "tasks",
            "modules",
            "Ctrl+G",
        ]
    );
    assert!(model.command_labels.contains(&"next"));
    assert!(!model.command_labels.contains(&"scan ."));
}

#[test]
fn home_cockpit_model_surfaces_invalid_latest_pointer() {
    let temp = tempfile::tempdir().unwrap();
    create_invalid_latest_pointer(temp.path());
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());

    let model = home_cockpit_model(&app);

    assert_eq!(model.run_card.run_id, "invalid latest pointer");
    assert_eq!(model.run_card.status, "no runs yet");
}

#[test]
fn home_cockpit_model_surfaces_blank_latest_pointer() {
    let temp = tempfile::tempdir().unwrap();
    write_blank_latest_pointer(temp.path());
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());

    let model = home_cockpit_model(&app);

    assert_eq!(model.run_card.run_id, "invalid latest pointer");
}

#[test]
fn run_status_label_surfaces_malformed_run_json() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join(run_metadata_artifact_leaf()), "{not-json").unwrap();

    assert_eq!(
        run_status_label(temp.path()),
        format!("malformed {}", run_metadata_artifact_leaf())
    );
}

#[test]
fn run_status_label_surfaces_non_object_run_json() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join(run_metadata_artifact_leaf()), "[]").unwrap();

    assert_eq!(
        run_status_label(temp.path()),
        format!("malformed {}", run_metadata_artifact_leaf())
    );
}

#[test]
fn run_status_label_surfaces_non_file_run_json() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join(run_metadata_artifact_leaf())).unwrap();

    assert_eq!(
        run_status_label(temp.path()),
        format!("{} is not a file", run_metadata_artifact_leaf())
    );
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

#[test]
fn placeholder_attack_surface_does_not_render_zero_risk() {
    let temp = tempfile::tempdir().unwrap();
    let run_dir = ui_run_dir(Some(temp.path()), "latest");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(
        run_dir.join("attack-surface.json"),
        r#"{"status":"skipped"}"#,
    )
    .unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());
    app.findings = vec![finding("sql-injection", kuzushi_core::Severity::High, 88)];

    let model = home_cockpit_model(&app);

    assert!(model.attack_surface.is_none());
    assert_eq!(model.findings_card.counts.high, 1);
    assert!(model.run_card.artifacts.iter().any(|artifact| {
        artifact.label == "surface" && artifact.state == "placeholder" && artifact.glyph == "○"
    }));
}

#[test]
fn findings_card_counts_reviewed_queue_and_top_risks() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.findings = vec![
        reviewed(finding(
            "command-injection",
            kuzushi_core::Severity::High,
            12,
        )),
        finding("path-traversal", kuzushi_core::Severity::Medium, 20),
        finding("sql-injection", kuzushi_core::Severity::High, 88),
    ];

    let model = home_cockpit_model(&app);

    assert_eq!(model.findings_card.total, 3);
    assert_eq!(model.findings_card.reviewed, 1);
    assert_eq!(model.findings_card.unreviewed, 2);
    assert_eq!(model.findings_card.counts.high, 2);
    assert_eq!(model.findings_card.counts.medium, 1);
    assert_eq!(model.findings_card.reviewed_counts.high, 1);
    assert_eq!(model.top_risks.len(), 3);
    assert!(model
        .top_risks
        .iter()
        .any(|row| row.rule == "sql-injection" && row.location == "src/lib.rs:88"));
}
