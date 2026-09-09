use super::*;
use crate::app::InputMode;
use kuzushi_core::V2Config;

fn app_with_config(target: &std::path::Path) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.to_path_buf()));
    app.open_batch_scan_config(None);
    assert_eq!(app.input_mode(), InputMode::Navigate);
    app
}

fn press(app: &mut ShellApp, code: KeyCode) {
    let update = app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE));
    assert!(update.handled);
    assert!(update.effects.is_empty(), "editing must not dispatch");
}

#[test]
fn enter_opens_direct_trial_input_and_saves_fifty_without_launching() {
    let target = tempfile::tempdir().unwrap();
    let mut app = app_with_config(target.path());
    press(&mut app, KeyCode::Enter);
    assert!(app.batch_number_editor_open());
    app.set_input("reserved shell draft".to_string());
    press(&mut app, KeyCode::Char('5'));
    press(&mut app, KeyCode::Char('0'));
    press(&mut app, KeyCode::Enter);
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.trials, 50);
    assert!(config.number_edit.is_none());
    assert!(!config.review_armed);
    assert_eq!(app.input(), "reserved shell draft");
    assert!(!target.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn invalid_values_keep_the_draft_and_prior_settings_until_cancel() {
    let target = tempfile::tempdir().unwrap();
    for value in [
        "",
        "1",
        "51",
        "-2",
        "2.5",
        "9999999999999999999999999",
        "Lqrw",
    ] {
        let mut app = app_with_config(target.path());
        press(&mut app, KeyCode::Enter);
        app.reduce_paste(value);
        press(&mut app, KeyCode::Enter);
        let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
        assert_eq!(config.trials, 3);
        let edit = config.number_edit.as_ref().unwrap();
        assert_eq!(edit.field.text(), value);
        assert!(edit.error.as_ref().unwrap().contains("2 to 50"));
        press(&mut app, KeyCode::Esc);
        assert!(!app.batch_number_editor_open());
        assert_eq!(app.shell_view(), ShellView::Campaign);
    }
}

#[test]
fn workers_accept_paste_and_cursor_edits_then_resolve_existing_policy() {
    let target = tempfile::tempdir().unwrap();
    let mut app = app_with_config(target.path());
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    assert!(app.reduce_paste("79").handled);
    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::Delete);
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Backspace);
    press(&mut app, KeyCode::Char('2'));
    press(&mut app, KeyCode::Enter);
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.requested_workers, 2);
    assert!((1..=2).contains(&config.effective_workers));
    assert!(config.number_edit.is_none());
}

#[test]
fn focused_field_consumes_launch_refresh_and_close_keys_and_keeps_exit_disclosure() {
    let target = tempfile::tempdir().unwrap();
    let mut app = app_with_config(target.path());
    press(&mut app, KeyCode::Enter);
    for ch in "Lrqwjk".chars() {
        press(&mut app, KeyCode::Char(ch));
    }
    assert!(app.batch_number_editor_open());
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .number_edit
            .as_ref()
            .unwrap()
            .field
            .text(),
        "Lrqwjk"
    );
    app.reduce_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert_eq!(app.shell_view(), ShellView::QuitConfirm);
    let plain = crate::renderer::render_plain_app(&app, 120);
    assert!(plain.contains("batch number draft"));
    press(&mut app, KeyCode::Char('n'));
    assert!(app.batch_number_editor_open());
}

#[test]
fn saving_a_number_disarms_review_and_never_silently_clamps() {
    let target = tempfile::tempdir().unwrap();
    let mut config = BatchScanConfig::load(target.path(), None);
    config.trials = 11;
    config.arm_review();
    config.begin_number_edit(BatchScanConfigRow::Trials);
    config.number_edit.as_mut().unwrap().field.insert("50");
    assert!(config.save_number_edit());
    assert!(!config.review_armed);
    assert!(config.needs_large_batch_review());
    config.begin_number_edit(BatchScanConfigRow::Workers);
    config.number_edit.as_mut().unwrap().field.insert("9");
    assert!(!config.save_number_edit());
    assert_eq!(config.requested_workers, 1);
}

#[test]
fn cancel_from_the_config_list_closes_the_form_without_changing_input_mode() {
    let target = tempfile::tempdir().unwrap();
    let mut app = app_with_config(target.path());
    press(&mut app, KeyCode::Esc);
    assert!(!app.batch_config_open());
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert_eq!(app.input_mode(), InputMode::Navigate);
}
