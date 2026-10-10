use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn app(target: &Path) -> ShellApp {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(target.to_owned()));
    app.router
        .report_mut()
        .prepare_choices_target(target.to_owned());
    app.set_shell_view(ShellView::Report);
    app.set_input_mode(InputMode::Navigate);
    app
}

fn choose_destination(app: &mut ShellApp, path: &str) {
    app.router.report_mut().set_editing_path(true);
    let route = app.router.report_mut();
    route.edit_path_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    route.insert_path_text(path);
    route.save_path_edit();
}

#[test]
fn restart_restores_format_destinations_and_completeness_without_export_or_authority() {
    let home = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let mut first = app(target.path());
    first.router.report_mut().move_format(3);
    first.router.report_mut().cycle_completeness();
    choose_destination(&mut first, "reports/owned-界.json");
    first.set_input("held operator draft");
    first.persist_report_choices_to(home.path());
    assert!(first
        .router
        .report()
        .choices_status()
        .contains("Saved for this target"));
    assert_eq!(first.input(), "held operator draft");
    let mut restarted = app(target.path());
    restarted.restore_report_choices_from(home.path());
    assert_eq!(restarted.router.report().format().as_str(), "json");
    assert_eq!(
        restarted.router.report().path_draft(),
        "reports/owned-界.json"
    );
    assert_eq!(restarted.router.report().completeness().as_str(), "open");
    assert!(restarted.router.report().study().is_none());
    assert!(restarted.router.report().receipt().is_none());
    assert!(!target.path().join("reports").exists());
    assert!(!restarted.tool_is_running());
}

#[test]
fn separate_target_starts_with_defaults_and_cannot_read_target_authored_preferences() {
    let home = tempfile::tempdir().unwrap();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let mut initial = app(first.path());
    initial.router.report_mut().move_format(3);
    initial.persist_report_choices_to(home.path());
    let mut other = app(second.path());
    let mut target_authored = other
        .router
        .report()
        .captured_choices(second.path().to_owned());
    target_authored.format = kuzushi_core::WorkspaceExportFormat::Csv;
    target_authored
        .destinations
        .insert("csv".into(), "target-steered.csv".into());
    save_report_preferences(second.path(), &target_authored).unwrap();
    other.restore_report_choices_from(home.path());
    assert_eq!(other.router.report().format().as_str(), "sarif");
    assert!(!other
        .router
        .report()
        .choices_status()
        .contains("Saved for this target"));
}

#[test]
fn failed_save_preserves_prior_saved_bytes_and_visible_choice() {
    let home = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let mut app = app(target.path());
    app.persist_report_choices_to(home.path());
    let before = load_report_preferences(home.path(), target.path())
        .unwrap()
        .unwrap();
    choose_destination(&mut app, &"x".repeat(4097));
    app.persist_report_choices_to(home.path());
    assert!(app.router.report().choices_status().contains("unavailable"));
    assert_eq!(app.router.report().path_draft().len(), 4097);
    assert_eq!(
        load_report_preferences(home.path(), target.path()).unwrap(),
        Some(before)
    );
}

#[test]
fn automatic_export_save_preserves_damaged_preferences_until_explicit_replace() {
    let home = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let mut app = app(target.path());
    app.persist_report_choices_to(home.path());
    let choices = app
        .router
        .report()
        .captured_choices(target.path().to_owned());
    let path = save_report_preferences(home.path(), &choices).unwrap();
    std::fs::write(&path, "{owned-damaged").unwrap();
    app.persist_report_export_choices_to(home.path(), target.path());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "{owned-damaged");
    assert!(app
        .router
        .report()
        .choices_status()
        .contains("S explicitly replaces"));
    app.persist_report_choices_to(home.path());
    assert!(load_report_preferences(home.path(), target.path())
        .unwrap()
        .is_some());
}

#[test]
fn save_key_emits_only_persistence_and_path_editor_keeps_input_ownership() {
    let target = tempfile::tempdir().unwrap();
    let mut app = app(target.path());
    app.set_input("held report draft");
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('S'), KeyModifiers::NONE));
    assert!(matches!(
        update.effects.as_slice(),
        [ShellEffect::PersistReportChoices]
    ));
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('S'), KeyModifiers::SHIFT));
    assert!(matches!(
        update.effects.as_slice(),
        [ShellEffect::PersistReportChoices]
    ));
    assert_eq!(app.input(), "held report draft");
    app.router.report_mut().set_editing_path(true);
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('S'), KeyModifiers::NONE));
    assert!(update.effects.is_empty());
    assert!(app.router.report().path_draft().contains('S'));
}
