use super::*;
use crate::app::BatchScanConfigRow;
use crate::ui_view_models::study_config::{study_config_layout, study_projection};
use crossterm::event::{KeyEvent, KeyModifiers};
use kuzushi_core::V2Config;

fn study() -> (tempfile::TempDir, ShellApp) {
    let target = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.path().to_path_buf()));
    app.open_batch_scan_config(None);
    app.set_input("preserved\ninput");
    app.set_cursor(3);
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.cursor = 3;
    config.detail_scroll = 2;
    config.notice = Some((0..90).map(|n| format!("Recorded detail {n}\n")).collect());
    (target, app)
}

fn key(app: &mut ShellApp, code: KeyCode) {
    let update = app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE));
    assert!(update.effects.is_empty());
}

#[test]
fn form_home_and_end_select_fields_without_editing_or_launching_work() {
    let (_target, mut app) = study();
    let before = study_projection(&app).unwrap().study;
    let view = app.shell_view();
    key(&mut app, KeyCode::End);
    assert_eq!(
        study_projection(&app).unwrap().selected_row(),
        BatchScanConfigRow::Launch
    );
    key(&mut app, KeyCode::Home);
    let config = study_projection(&app).unwrap();
    assert_eq!(config.selected_row(), BatchScanConfigRow::Trials);
    assert_eq!(config.study, before);
    assert_eq!((app.input(), app.cursor()), ("preserved\ninput", 3));
    assert_eq!(app.shell_view(), view);
    assert!(app.activity().is_none());
}

#[test]
fn numeric_editor_owns_home_and_end_without_changing_the_selected_field() {
    let (_target, mut app) = study();
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.cursor = 5;
    config.begin_number_edit(BatchScanConfigRow::ProviderCalls);
    for code in [
        KeyCode::Char('1'),
        KeyCode::Char('2'),
        KeyCode::Home,
        KeyCode::Char('9'),
        KeyCode::End,
        KeyCode::Char('3'),
    ] {
        key(&mut app, code);
    }
    let config = study_projection(&app).unwrap();
    assert_eq!(config.selected_row(), BatchScanConfigRow::ProviderCalls);
    assert_eq!(config.number_edit.as_ref().unwrap().field.text(), "9123");
    assert_eq!((app.input(), app.cursor()), ("preserved\ninput", 3));
}

#[test]
fn reader_increases_space_at_all_viewports_and_keeps_controls_in_bounds() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (120, 36), (160, 48), (96, 89)] {
        let area = study_config_area(width, height);
        let form = study_config_layout(area);
        let reader = study_reader_layout(area, true);
        assert!(reader.detail.width >= form.detail.width);
        assert!(reader.detail.height >= form.detail.height);
        assert_eq!(reader.list.height, 0);
        assert_eq!(reader.controls, form.controls);
        assert!(reader.detail.bottom() <= reader.controls.top());
    }
    assert_eq!(
        study_reader_layout(study_config_area(40, 12), true)
            .detail
            .height,
        6
    );
}

#[test]
fn reader_scroll_is_independent_and_escape_restores_the_original_form() {
    let (_target, mut app) = study();
    key(&mut app, KeyCode::Char('z'));
    key(&mut app, KeyCode::PageDown);
    let reading = study_projection(&app).unwrap();
    assert!(reading.detail_reader_scroll.unwrap() > 2);
    assert_eq!(reading.detail_scroll, 2);
    key(&mut app, KeyCode::Esc);
    let restored = study_projection(&app).unwrap();
    assert!(restored.detail_reader_scroll.is_none());
    assert_eq!(restored.detail_scroll, 2);
    assert_eq!(restored.selected_row(), BatchScanConfigRow::Context);
    assert_eq!((app.input(), app.cursor()), ("preserved\ninput", 3));
}

#[test]
fn arrows_scroll_document_and_resize_preserves_the_selected_setting() {
    let (_target, mut app) = study();
    key(&mut app, KeyCode::Char('z'));
    key(&mut app, KeyCode::Down);
    let config = study_projection(&app).unwrap();
    assert_eq!(config.detail_reader_scroll, Some(3));
    assert_eq!(config.cursor, 3);
    key(&mut app, KeyCode::Home);
    assert_eq!(
        study_projection(&app).unwrap().detail_reader_scroll,
        Some(0)
    );
    app.reduce_resize(40, 12);
    key(&mut app, KeyCode::End);
    assert_eq!(study_projection(&app).unwrap().cursor, 3);
    assert!(
        study_projection(&app)
            .unwrap()
            .detail_reader_scroll
            .unwrap()
            > 10
    );
    key(&mut app, KeyCode::Char('z'));
    assert_eq!(study_projection(&app).unwrap().detail_scroll, 2);
}

#[test]
fn retained_failure_can_expand_and_dismiss_without_closing_the_draft() {
    let (_target, mut app) = study();
    app.study_preparation_failed("campaign:study", "Recorded preparation failure");
    key(&mut app, KeyCode::Char('z'));
    assert!(study_projection(&app)
        .unwrap()
        .detail_reader_scroll
        .is_some());
    key(&mut app, KeyCode::Esc);
    let restored = study_projection(&app).unwrap();
    assert!(restored.detail_reader_scroll.is_none());
    assert!(restored.study.preparation_error.is_none());
    assert_eq!(restored.cursor, 3);
}

#[test]
fn reader_offset_handles_boundaries_and_preserves_unowned_keys() {
    assert_eq!(reader_offset(KeyCode::Up, 0, 3), Some(0));
    assert_eq!(reader_offset(KeyCode::Down, 3, 3), Some(3));
    assert_eq!(reader_offset(KeyCode::Char('L'), 2, 3), None);
}
