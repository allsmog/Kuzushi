use super::*;
use crossterm::event::{KeyEvent, KeyModifiers};
use kuzushi_core::V2Config;

fn app() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.open_batch_scan_config(None);
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .cursor = 3;
    app.set_input("preserved\ndraft");
    app.set_cursor(4);
    (root, app)
}

#[test]
fn switching_views_preserves_independent_form_and_reader_positions() {
    let mut state = StudySourceState::default();
    let mut form = 4;
    let mut reader = Some(8);
    state.switch(false, &mut form, &mut reader);
    assert_eq!((form, reader), (0, Some(0)));
    form = 3;
    reader = Some(6);
    state.switch(true, &mut form, &mut reader);
    assert_eq!(
        (state.selected, form, reader),
        (StudySourceView::Overview, 4, Some(8))
    );
    state.switch(false, &mut form, &mut reader);
    assert_eq!((form, reader), (3, Some(6)));
}

#[test]
fn all_four_views_keep_independent_form_and_reader_offsets() {
    let mut state = StudySourceState::default();
    let mut form = 0;
    let mut reader = Some(0);
    for index in 0..4 {
        form = index + 10;
        reader = Some(index + 20);
        state.switch(false, &mut form, &mut reader);
    }
    for index in 0..4 {
        assert_eq!((form, reader), (index + 10, Some(index + 20)));
        state.switch(false, &mut form, &mut reader);
    }
}

#[test]
fn keyboard_switching_wraps_both_directions_without_dispatch_or_losing_input() {
    let (root, mut app) = app();
    for key in [
        KeyCode::Tab,
        KeyCode::Tab,
        KeyCode::Tab,
        KeyCode::Tab,
        KeyCode::BackTab,
    ] {
        let update = app.reduce_key(KeyEvent::new(key, KeyModifiers::NONE));
        assert!(update.effects.is_empty());
    }
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.source_view.selected, StudySourceView::Options);
    assert_eq!(config.cursor, 3);
    assert_eq!((app.input(), app.cursor()), ("preserved\ndraft", 4));
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn shift_tab_encoding_and_other_fields_keep_their_input_owner() {
    let (_root, mut app) = app();
    app.reduce_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT));
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .source_view
            .selected,
        StudySourceView::Options
    );
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .cursor = 0;
    app.reduce_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .source_view
            .selected,
        StudySourceView::Options
    );
}

#[test]
fn retained_error_blocks_source_tabs_and_keeps_dismissal_priority() {
    let (_root, mut app) = app();
    app.study_preparation_failed("campaign:study", "Owned failure");
    app.clear_notice();
    app.reduce_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .source_view
            .selected,
        StudySourceView::Overview
    );
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.batch_config_open());
    assert!(!app.study_notice_captures_escape());
}

#[test]
fn reader_return_keeps_the_selected_source_view() {
    let (_root, mut app) = app();
    for key in [KeyCode::Tab, KeyCode::Char('z'), KeyCode::Tab, KeyCode::Esc] {
        app.reduce_key(KeyEvent::new(key, KeyModifiers::NONE));
    }
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.source_view.selected, StudySourceView::Settings);
    assert!(config.detail_reader_scroll.is_none());
}
