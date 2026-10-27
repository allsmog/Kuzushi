use super::*;
use crate::{InputMode, ShellView};

fn study_app() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join(".kuzushi/v3/campaigns/header-study");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("plan.json"),
        serde_json::json!({
            "kind":"scan-batch", "jobs":[{"jobId":"trial-1","input":{}}]
        })
        .to_string(),
    )
    .unwrap();
    let snapshot = kuzushi_core::capabilities::campaign::snapshot::load_campaign_snapshot(
        root.path(),
        "header-study",
    )
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    app.set_shell_view(ShellView::Campaign);
    app.router.campaign_mut().campaigns = vec![snapshot];
    app.router.campaign_mut().detail = true;
    (root, app)
}

#[test]
fn fixed_study_headers_name_the_reader_and_target_without_changing_input_or_progress() {
    let (_root, mut app) = study_app();
    app.set_focused_module(Some("semgrep".into()));
    app.set_input("Retained 東京 draft\nsecond line");
    app.set_cursor(4);
    app.router.campaign_mut().read_scroll = 7;
    for mode in [InputMode::Prompt, InputMode::Navigate] {
        app.set_input_mode(mode);
        let before = app.router.campaign().clone();
        let model = context_strip_model(&app);
        let rows = model.orientation_segments();
        assert_eq!(rows[0], "Study jobs");
        assert_eq!(rows[1], format!("Target {}", model.target));
        assert!(rows.contains(&"Progress Map 1/3".into()));
        assert!(rows
            .iter()
            .all(|row| !row.contains("view:") && !row.contains("phase:")));
        assert_eq!(model.mode, "Module selected");
        assert_eq!(app.router.campaign(), &before);
        assert_eq!(
            (app.input(), app.cursor()),
            ("Retained 東京 draft\nsecond line", 4)
        );
    }
}

#[test]
fn study_job_title_tracks_the_reader_without_claiming_approval_or_completion() {
    let (_root, mut app) = study_app();
    app.router.campaign_mut().job_detail = true;
    let model = context_strip_model(&app);
    assert_eq!(model.study_title, Some("Study job"));
    assert_eq!(model.phase.as_deref(), Some("Map 1/3"));
    assert!(model
        .status_segments()
        .contains(&"configured model:unconfigured".into()));
    assert_eq!(
        app.router.campaign().selected_job().unwrap().state,
        "planned"
    );
}

#[test]
fn legacy_history_lists_and_other_views_keep_their_existing_orientation() {
    let (_root, mut app) = study_app();
    app.router.campaign_mut().detail = false;
    assert_eq!(context_strip_model(&app).study_title, None);
    app.router.campaign_mut().detail = true;
    app.router.campaign_mut().campaigns[0].kind = None;
    assert_eq!(context_strip_model(&app).study_title, None);
    app.set_shell_view(ShellView::Logs);
    assert_eq!(context_strip_model(&app).study_title, None);
    assert_eq!(context_strip_model(&app).model_field_label(), "model");
}

#[test]
fn active_forms_own_their_heading_while_parked_drafts_do_not_hide_the_study_reader() {
    let (root, mut app) = study_app();
    let draft = crate::app::BatchScanConfig::load(root.path(), None);
    app.router.campaign_mut().setup_context_study = Some(draft.clone());
    assert_eq!(context_strip_model(&app).study_title, Some("Study jobs"));
    app.router.campaign_mut().batch_scan_config = Some(draft);
    assert_eq!(context_strip_model(&app).study_title, None);
}
