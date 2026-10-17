use super::*;
use serde_json::json;

fn payload(root: &std::path::Path) -> serde_json::Value {
    json!({"status":"partial","data":{"target":root,"rows":[{"rank":1,"path":"owned.c","citations":[]}],
        "rankedTotal":1,"contributors":{"systemsHunt":"live"}}})
}

fn fixture() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let dir = kuzushi_core::workspace::workspace_state_dir(root.path()).join("runs/saved-owned");
    std::fs::create_dir_all(&dir).unwrap();
    let mut summary = kuzushi_core::RunSummary::running(
        "saved-owned",
        "tool",
        Some("worklist:rank".into()),
        root.path().display().to_string(),
    );
    summary.status = "partial".into();
    std::fs::write(dir.join("run.json"), serde_json::to_vec(&summary).unwrap()).unwrap();
    std::fs::write(dir.join("result.json"), payload(root.path()).to_string()).unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.set_shell_view(crate::ShellView::Scene);
    app.router
        .scene_mut()
        .set_page(crate::scene3d::VizPage::Worklist);
    for _ in 0..3 {
        app.hydrate_active_view_blocking();
    }
    (root, app)
}

#[test]
fn cold_reader_restores_saved_ranking_with_unverified_context_and_source() {
    let (_root, app) = fixture();
    let model = worklist_model(&app);
    assert_eq!(model.rows[0].location, "owned.c");
    let text = model.inspection.join("\n");
    assert!(text.contains("Saved ranking from saved-owned"));
    assert!(text.contains("unverified"));
    assert!(text.contains("unrecorded"));
}

#[test]
fn malformed_or_foreign_saved_payload_is_refused() {
    let root = tempfile::tempdir().unwrap();
    for value in [
        json!({}),
        json!({"status":"failed","data":payload(root.path())["data"]}),
        payload(std::path::Path::new("/another-owned-target")),
    ] {
        assert!(checked_projection(&value, root.path(), "saved-owned").is_err());
    }
}

#[test]
fn render_uses_hydrated_identity_until_an_explicit_refresh() {
    let (root, app) = fixture();
    let before = worklist_model(&app);
    let path = kuzushi_core::workspace::workspace_state_dir(root.path())
        .join("runs/saved-owned/result.json");
    std::fs::write(path, "{}").unwrap();
    assert_eq!(worklist_model(&app), before);
}

#[test]
fn a_captured_result_is_not_replaced_with_historical_rows_after_context_drift() {
    let (root, mut app) = fixture();
    app.domain_mut().set_worklist_snapshot(
        root.path().to_path_buf(),
        Some(999),
        Some(payload(root.path())["data"].clone()),
    );
    assert!(saved_run(&app).unwrap().is_none());
    assert!(!reads_saved_worklist(&app));
}

#[test]
fn map_does_not_replace_current_context_projection_with_historical_ranking() {
    let (_root, mut app) = fixture();
    app.set_shell_view(crate::ShellView::Workbench);
    assert!(saved_run(&app).unwrap().is_none());
}

#[test]
fn inconsistent_saved_counts_and_oversized_row_sets_are_refused() {
    let root = tempfile::tempdir().unwrap();
    let mut value = payload(root.path());
    value["data"]["rankedTotal"] = json!(0);
    assert!(checked_projection(&value, root.path(), "saved-owned").is_err());
    value["data"]["rows"] = json!(vec![json!({"rank":1,"path":"owned.c"}); 501]);
    value["data"]["rankedTotal"] = json!(501);
    assert!(checked_projection(&value, root.path(), "saved-owned").is_err());
}
