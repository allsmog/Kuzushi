use super::*;
use kuzushi_core::V2Config;

fn context_snapshot_fixture_path() -> std::path::PathBuf {
    kuzushi_core::context_snapshot_path("")
}

#[test]
fn context_snapshot_relative_path_uses_core_context_path() {
    assert_eq!(
        context_snapshot_relative_path(),
        kuzushi_core::context_snapshot_path("")
            .display()
            .to_string()
    );
}

#[test]
fn context_snapshot_model_projects_present_snapshot() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut()
        .set_context_view(crate::app::ContextSnapshotView {
            snapshot_path: Some(context_snapshot_fixture_path()),
            exists: true,
            status: "snapshot present; 2 indexed file(s)".to_string(),
            target: Some("/tmp/demo".to_string()),
            discovery: Some("auto".to_string()),
            files_indexed: Some(2),
            total_files: Some(3),
            languages: vec!["Rust".to_string()],
            frameworks: vec!["Cargo".to_string()],
            generated_slices: vec!["repo".to_string(), "app-model".to_string()],
            stale_slices: Vec::new(),
        });

    let model = context_snapshot_model(&app);

    assert_eq!(model.snapshot, "./context-snapshot.json");
    assert!(model.snapshot_present);
    assert_eq!(model.state, "present");
    assert_eq!(model.status, "snapshot present; 2 indexed file(s)");
    let details = model.details.expect("present details");
    assert_eq!(details.target, "/tmp/demo");
    assert_eq!(details.files, "indexed=2 total=3");
    assert_eq!(details.languages, "Rust");
    assert_eq!(details.stale, "-");
}

#[test]
fn context_snapshot_model_reports_running_context_tool() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_running_tool_for_test("context:build");

    let model = context_snapshot_model(&app);

    assert_eq!(model.state, "missing");
    assert!(!model.snapshot_present);
    assert!(model
        .status
        .contains("context:build indexing repository context"));
    assert_eq!(
        model.running.expect("running context").message,
        "building snapshot; this view updates when the worker finishes"
    );
    assert!(model.details.is_none());
}

#[test]
fn plain_context_model_projects_missing_snapshot_rows() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = plain_context_model(&app);

    assert_eq!(model.title, "CONTEXT");
    assert!(model
        .summary_rows
        .contains(&format!("snapshot: {}", context_snapshot_relative_path())));
    assert!(model.summary_rows.contains(&"state: missing".to_string()));
    assert!(model.body_rows.contains(&format!(
        "No context snapshot exists yet. Next: context build writes {}.",
        context_snapshot_relative_path()
    )));
    assert_eq!(
        model.next_hint,
        "Next: context build, context status, context regen repo"
    );
}

#[test]
fn plain_context_model_projects_malformed_snapshot_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut().context_view_mut().snapshot_path = Some(context_snapshot_fixture_path());
    app.domain_mut().context_view_mut().status =
        "malformed context snapshot. Next: context build".to_string();

    let model = plain_context_model(&app);

    assert!(model.summary_rows.contains(&"state: malformed".to_string()));
    assert!(model
        .summary_rows
        .contains(&"status: malformed context snapshot. Next: context build".to_string()));
    assert!(model.body_rows.contains(&format!(
        "Context snapshot is malformed JSON. Next: context build rewrites {}.",
        context_snapshot_relative_path()
    )));
}

#[test]
fn plain_context_model_projects_non_file_snapshot_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut().context_view_mut().snapshot_path = Some(context_snapshot_fixture_path());
    app.domain_mut().context_view_mut().status =
        "malformed context snapshot (not a file). Next: context build".to_string();

    let model = plain_context_model(&app);

    assert!(model.summary_rows.contains(&"state: malformed".to_string()));
    assert!(model.summary_rows.contains(
        &"status: malformed context snapshot (not a file). Next: context build".to_string()
    ));
    assert!(model.body_rows.contains(&format!(
        "Context snapshot path is not a file. Next: context build rewrites {}.",
        context_snapshot_relative_path()
    )));
}

#[test]
fn plain_context_model_projects_present_snapshot_details() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut()
        .set_context_view(crate::app::ContextSnapshotView {
            snapshot_path: Some(context_snapshot_fixture_path()),
            exists: true,
            status: "snapshot present; 2 indexed file(s)".to_string(),
            target: Some("/tmp/demo".to_string()),
            discovery: Some("auto".to_string()),
            files_indexed: Some(2),
            total_files: Some(3),
            languages: vec!["Rust".to_string()],
            frameworks: vec!["Cargo".to_string()],
            generated_slices: vec!["repo".to_string(), "app-model".to_string()],
            stale_slices: Vec::new(),
        });

    let model = plain_context_model(&app);

    assert!(model.summary_rows.contains(&"state: present".to_string()));
    assert!(model.body_rows.contains(&"target: /tmp/demo".to_string()));
    assert!(model
        .body_rows
        .contains(&"files: indexed=2 total=3".to_string()));
    assert!(model.body_rows.contains(&"stale: -".to_string()));
}
