use super::*;
use kuzushi_core::V2Config;
use std::path::PathBuf;

#[test]
fn context_snapshot_model_projects_present_snapshot() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.context_view = crate::app::ContextSnapshotView {
        snapshot_path: Some(PathBuf::from(".kuzushi/context-snapshot.json")),
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
    };

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
