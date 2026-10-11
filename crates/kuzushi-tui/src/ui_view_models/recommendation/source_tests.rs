use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::json;
use std::fs;

fn write_run(root: &Path, id: &str, tool: &str, status: &str, started: u64) {
    let dir = ui_run_dir(Some(root), id);
    fs::create_dir_all(&dir).unwrap();
    let mut summary = kuzushi_core::RunSummary::running(
        id,
        "tool",
        Some(tool.to_owned()),
        root.display().to_string(),
    );
    summary.status = status.to_owned();
    summary.started_at_unix = started;
    fs::write(dir.join("run.json"), serde_json::to_vec(&summary).unwrap()).unwrap();
    fs::write(super::ui_latest_run_path(Some(root)), id).unwrap();
}

fn write_report(root: &Path, id: &str) {
    fs::write(
        ui_run_dir(Some(root), id).join("result.json"),
        json!({"status":"completed","data":{"rankingMode":"deterministic",
        "recommendations":[{"tool":"repository-inventory:build","reason":"Owned metadata"}]}})
        .to_string(),
    )
    .unwrap();
}

fn hydrated_app(root: &Path) -> ShellApp {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(root.to_owned()));
    app.hydrate_all_view_data_for_test();
    app
}

#[test]
fn recommendation_reader_keys_scroll_without_entering_the_composer() {
    let temp = tempfile::tempdir().unwrap();
    write_run(
        temp.path(),
        "report",
        "module-recommender:recommend",
        "completed",
        10,
    );
    write_report(temp.path(), "report");
    let mut app = hydrated_app(temp.path());
    app.set_shell_view(crate::ShellView::Recommend);
    app.set_input_mode(crate::InputMode::Navigate);
    app.set_viewport(crate::TerminalViewport::new(40, 12));
    assert!(
        app.reduce_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE))
            .handled
    );
    assert!(
        app.router.default_scroll().offset() <= 12,
        "Paging skipped more than the terminal's height."
    );
    for code in [KeyCode::PageDown, KeyCode::Char('G')] {
        assert!(
            app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE))
                .handled
        );
        assert!(app.router.default_scroll().offset() > 0);
        assert!(app.input().is_empty());
        assert_eq!(app.input_mode(), crate::InputMode::Navigate);
    }
    let footer = crate::ui_view_models::footer_keybindings(&app);
    assert!(footer.iter().any(|binding| binding.key == "r"));
    assert!(!footer
        .iter()
        .any(|binding| binding.label.contains("component")));
    assert!(!footer.iter().any(|binding| binding.label.contains("scan")));
}

#[test]
fn recommendation_pending_reader_does_not_claim_missing_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(temp.path().to_owned()));
    assert_eq!(
        recommendation_model(&app).empty_state.title,
        "loading generated suggestions"
    );
}

#[test]
fn recommendation_reopen_refreshes_history_after_external_report_publication() {
    let temp = tempfile::tempdir().unwrap();
    write_run(
        temp.path(),
        "old",
        "module-recommender:recommend",
        "completed",
        10,
    );
    write_report(temp.path(), "old");
    let mut app = hydrated_app(temp.path());
    assert_eq!(recommendation_run_id(&app).as_deref(), Some("old"));
    write_run(
        temp.path(),
        "new",
        "module-recommender:recommend",
        "partial",
        20,
    );
    write_report(temp.path(), "new");
    let effects = app
        .reduce_command_effects(&crate::commands::parse_command("recommendations"))
        .unwrap();
    assert!(effects.is_empty());
    app.hydrate_all_view_data_for_test();
    assert_eq!(recommendation_run_id(&app).as_deref(), Some("new"));
    assert!(recommendation_model(&app).detail_rows[0].cells[1].contains("/new/result.json"));
}

#[test]
fn recommendation_canonical_result_is_read_without_retired_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    write_run(
        temp.path(),
        "report",
        "module-recommender:recommend",
        "completed",
        10,
    );
    write_report(temp.path(), "report");
    let app = hydrated_app(temp.path());
    let model = recommendation_model(&app);
    assert_eq!(model.rows[0].cells[1], "repository-inventory:build");
    assert!(model.detail_rows[0].cells[1].ends_with("/result.json"));
    assert!(model
        .detail_rows
        .iter()
        .any(|r| r.cells[1] == "deterministic; no model request"));
    assert!(!model.detail_rows.iter().any(|r| r.cells[0] == "history"));
}

#[test]
fn recommendation_earlier_report_survives_failed_and_unrelated_latest_activity() {
    for (tool, status) in [
        ("module-recommender:recommend", "failed"),
        ("source:inspect", "completed"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        write_run(
            temp.path(),
            "report",
            "module-recommender:recommend",
            "partial",
            10,
        );
        write_report(temp.path(), "report");
        write_run(temp.path(), "newer", tool, status, 20);
        let app = hydrated_app(temp.path());
        let model = recommendation_model(&app);
        assert_eq!(recommendation_run_id(&app).as_deref(), Some("report"));
        assert_eq!(model.rows[0].cells[1], "repository-inventory:build");
        assert!(model.detail_rows.iter().any(|r| r.cells[0] == "history"
            && r.cells[1].contains("latest activity is newer")
            && r.cells[1].contains("100 runs")));
    }
}

#[test]
fn recommendation_malformed_canonical_result_is_not_hidden_by_legacy_report() {
    let temp = tempfile::tempdir().unwrap();
    write_run(
        temp.path(),
        "report",
        "module-recommender:recommend",
        "completed",
        10,
    );
    let dir = ui_run_dir(Some(temp.path()), "report");
    fs::write(dir.join("result.json"), "{broken").unwrap();
    fs::write(
        dir.join("recommendations.json"),
        json!({"recommendations":[]}).to_string(),
    )
    .unwrap();
    let model = recommendation_model(&hydrated_app(temp.path()));
    assert_eq!(model.summary.as_deref(), Some("malformed result.json"));
    assert_eq!(model.rows[0].cells[1], "result.json");
}

#[test]
fn recommendation_invalid_latest_pointer_does_not_silently_select_older_history() {
    let temp = tempfile::tempdir().unwrap();
    write_run(
        temp.path(),
        "report",
        "module-recommender:recommend",
        "completed",
        10,
    );
    write_report(temp.path(), "report");
    fs::write(super::ui_latest_run_path(Some(temp.path())), "../unsafe").unwrap();
    let app = hydrated_app(temp.path());
    assert_eq!(recommendation_run_id(&app), None);
    let model = recommendation_model(&app);
    assert!(model.rows.is_empty());
    assert!(model
        .detail_rows
        .iter()
        .any(|r| r.cells[1] == "invalid latest pointer"));
}
