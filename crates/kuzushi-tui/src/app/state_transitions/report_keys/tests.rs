use crate::app::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn editor() -> ShellApp {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_shell_view(ShellView::Report);
    app.set_input_mode(InputMode::Navigate);
    app.set_input("retained composer");
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
    assert!(update.handled && update.effects.is_empty());
    assert!(app.router.report().editing_path());
    app
}

fn press(app: &mut ShellApp, code: KeyCode, modifiers: KeyModifiers) {
    let update = app.reduce_key(KeyEvent::new(code, modifiers));
    assert!(update.handled && update.effects.is_empty());
    assert_eq!(app.input(), "retained composer");
    assert!(!app.has_running_work());
}

#[test]
fn report_destination_cursor_delete_and_escape_restore_saved_path() {
    let mut app = editor();
    let original = app.router.report().path_draft().to_string();
    press(&mut app, KeyCode::Home, KeyModifiers::NONE);
    press(&mut app, KeyCode::Char('界'), KeyModifiers::SHIFT);
    assert_eq!(app.router.report().path_draft(), format!("界{original}"));
    press(&mut app, KeyCode::Delete, KeyModifiers::NONE);
    assert_eq!(
        app.router.report().path_draft(),
        format!("界{}", &original[1..])
    );
    press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    assert_eq!(app.router.report().path_draft(), original);
    assert!(!app.router.report().editing_path());
}

#[test]
fn report_destination_paste_and_save_stay_in_the_field() {
    let mut app = editor();
    press(&mut app, KeyCode::Char('u'), KeyModifiers::CONTROL);
    assert_eq!(app.router.report().path_draft(), "");
    let update = app.reduce_paste(".kuzushi/reports/review, 界.json");
    assert!(update.handled && update.effects.is_empty());
    assert_eq!(app.input(), "retained composer");
    assert_eq!(
        app.router.report().path_draft(),
        ".kuzushi/reports/review, 界.json"
    );
    press(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
    assert!(!app.router.report().editing_path());
    assert_eq!(
        app.router.report().path_draft(),
        ".kuzushi/reports/review, 界.json"
    );
}

#[test]
fn report_destination_invalid_draft_stays_editable_and_can_be_canceled() {
    for draft in ["", "one\ntwo", "bad\0path"] {
        let mut app = editor();
        let original = app.router.report().path_draft().to_string();
        press(&mut app, KeyCode::Char('u'), KeyModifiers::CONTROL);
        app.router.report_mut().insert_path_text(draft);
        press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert!(app.router.report().editing_path());
        assert!(app.router.report().path_error().is_some());
        assert_eq!(app.router.report().path_draft(), draft);
        press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(app.router.report().path_draft(), original);
    }
}

#[test]
fn report_destination_formats_preserve_their_saved_paths() {
    let mut app = editor();
    press(&mut app, KeyCode::Char('u'), KeyModifiers::CONTROL);
    app.reduce_paste(".kuzushi/reports/my review.sarif");
    press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    app.router.report_mut().move_format(1);
    assert_eq!(app.router.report().path_draft(), ".kuzushi/reports/report/");
    app.router.report_mut().move_format(-1);
    assert_eq!(
        app.router.report().path_draft(),
        ".kuzushi/reports/my review.sarif"
    );
}

#[test]
fn report_destination_quit_and_stay_preserve_the_unsaved_field() {
    let mut app = editor();
    app.set_input("");
    app.router.report_mut().insert_path_text(" unsaved 界");
    app.reduce_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    let field = app.router.report().path_edit().unwrap().clone();
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(update.effects.is_empty());
    assert_eq!(app.shell_view(), ShellView::QuitConfirm);
    let warning = crate::ui_view_models::quit_confirm_model(&app);
    assert!(format!("{warning:?}").contains("report destination draft"));
    assert!(!format!("{warning:?}").contains("unsaved 界"));
    app.reduce_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!(app.router.report().path_edit(), Some(&field));
    assert!(!app.should_quit());
}
