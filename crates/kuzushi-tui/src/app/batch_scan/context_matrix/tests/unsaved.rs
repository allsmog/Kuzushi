use super::*;

#[test]
fn quitting_unprepared_cases_discloses_loss_without_private_names() {
    let (_root, mut app) = fixture();
    let update = app.reduce_quit_chord_for_test();
    assert!(update.effects.is_empty());
    assert_eq!(app.shell_view(), ShellView::QuitConfirm);
    assert!(!app.should_quit());
    let model = crate::ui_view_models::quit_confirm_model(&app);
    let text = format!("{model:?}");
    assert!(text.contains("study choices"));
    assert!(text.contains("uncheckpointed"));
    assert!(!text.contains("Alpha"));
    assert!(!text.contains("Beta"));
}

#[test]
fn hidden_empty_name_is_still_an_unsaved_edit() {
    let (_root, mut app) = fixture();
    app.begin_context_case_name_edit();
    app.handle_context_case_name_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    app.handle_context_case_name_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    let matrix = &app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .matrix;
    assert!(matrix.has_unsaved_name());
    assert!(!matrix.name_edit.as_ref().unwrap().open);
    assert_eq!(matrix.cases[0].label, "Alpha");
    assert_eq!(matrix.name_edit.as_ref().unwrap().field.text(), "");
}

#[test]
fn unchanged_names_and_removed_cases_do_not_create_phantom_drafts() {
    let (_root, mut app) = fixture();
    app.begin_context_case_name_edit();
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    assert!(!config.study.matrix.has_unsaved_name());
    config.study.matrix.cases.clear();
    assert!(!config.study.matrix.has_unsaved_changes());
}

#[test]
fn staying_after_quit_restores_the_name_cursor_and_case_selection() {
    let (_root, mut app) = fixture();
    app.handle_context_matrix_key(KeyCode::Down);
    app.begin_context_case_name_edit();
    app.handle_context_case_name_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
    app.capture_context_case_name_paste("Private ");
    let before = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .clone();
    app.reduce_quit_chord_for_test();
    app.reduce_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert_eq!(
        app.router.campaign().batch_scan_config.as_ref(),
        Some(&before)
    );
    assert!(app.context_case_name_editor_open());
}

#[test]
fn leaving_a_study_keeps_unprepared_cases_until_explicitly_cleared() {
    let (_root, mut app) = fixture();
    let origin = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .origin
        .clone()
        .unwrap();
    app.handle_context_matrix_key(KeyCode::Down);
    app.handle_context_matrix_key(KeyCode::Esc);
    app.close_batch_config();
    assert_eq!(app.shell_view(), ShellView::Campaign);
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.study.matrix.cases.len(), 2);
    assert_eq!(config.study.matrix.cursor, 1);
    assert!(config.study.matrix.open);
    assert!(config.notice.as_ref().unwrap().contains("not saved yet"));
    app.handle_context_matrix_key(KeyCode::Char('c'));
    app.close_batch_config();
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .draft_recovery,
        crate::app::StudyDraftRecovery::Discard
    );
    app.handle_batch_config_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
    assert_eq!(app.shell_view(), origin.view);
    assert_eq!(app.input_mode(), origin.mode);
    assert!(app.router.campaign().batch_scan_config.is_none());
}
