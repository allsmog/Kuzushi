use super::*;

fn prepared_reader() -> (tempfile::TempDir, ShellApp) {
    let (root, mut app) = fixture();
    let result = prepare(&mut app, root.path());
    app.cache_review_study_result(&result["data"]);
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.max_provider_calls = Some(5);
    config.study.protected_review_calls = Some(2);
    app.handle_review_study_key(KeyCode::Char('v'));
    (root, app)
}

#[test]
fn review_source_reader_enter_cannot_approve_the_prepared_allowance() {
    let (_root, mut app) = prepared_reader();
    let before = app.router.campaign().batch_scan_config.clone();
    let update = app.handle_review_study_key(KeyCode::Enter);
    assert!(
        update.effects.is_empty(),
        "Reading evidence must not emit an approval dispatch; got {} effects",
        update.effects.len()
    );
    assert_eq!(app.router.campaign().batch_scan_config, before);
    assert!(!app.has_running_work());
}

#[test]
fn review_source_reader_ignores_hidden_plan_editing_shortcuts() {
    let (_root, mut app) = prepared_reader();
    let before = app.router.campaign().batch_scan_config.clone();
    for key in ['n', 's', 'e', 'c', 'M', 't', 'r'] {
        assert!(app
            .handle_review_study_key(KeyCode::Char(key))
            .effects
            .is_empty());
        assert_eq!(
            app.router.campaign().batch_scan_config,
            before,
            "reader key {key} edited the plan"
        );
    }
    app.handle_review_study_key(KeyCode::Char('v'));
    app.handle_review_study_key(KeyCode::Char('n'));
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .review_receipt
        .is_none());
}

#[test]
fn review_source_reader_preserves_visible_navigation_and_file_selection() {
    let (root, mut app) = fixture();
    for key in ['s', 's', 'e'] {
        app.handle_review_study_key(KeyCode::Char(key));
    }
    let result = prepare(&mut app, root.path());
    app.cache_review_study_result(&result["data"]);
    app.handle_review_study_key(KeyCode::Char('v'));
    let original = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .review_plan
        .as_ref()
        .unwrap()
        .input
        .clone();
    app.set_viewport(crate::TerminalViewport::new(40, 12));
    app.handle_review_study_key(KeyCode::End);
    assert!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .review_plan
            .as_ref()
            .unwrap()
            .scroll
            > 0
    );
    app.handle_review_study_key(KeyCode::Home);
    app.handle_review_study_key(KeyCode::Char('f'));
    assert_eq!(app.shell_view(), ShellView::FilePicker);
    app.handle_file_picker_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .review_plan
            .as_ref()
            .unwrap()
            .show_evidence
    );
    app.handle_review_study_key(KeyCode::Tab);
    let review = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .review_plan
        .as_ref()
        .unwrap();
    assert!(review.show_options && !review.show_evidence);
    assert_eq!(review.input, original);
}
