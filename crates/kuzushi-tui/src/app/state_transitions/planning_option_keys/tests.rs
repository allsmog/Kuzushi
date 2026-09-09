use super::*;
use crate::app::{PlanningArtifactState, PlanningOptionEdit, PlanningTaskRow};

fn editor(name: &str, draft: &str, setup: bool) -> ShellApp {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let task = PlanningTaskId::GatherRepoContext;
    let row = PlanningTaskRow {
        id: task,
        label: task.label(),
        tool_name: task.tool_name(),
        artifact_path: "/unused-test-artifact".into(),
        artifact_state: PlanningArtifactState::Missing,
        artifact_modified: None,
        model_backed: false,
        required_cli: None,
        cli_available: true,
        blocker: None,
        cached_detail: None,
        last_attempt: None,
    };
    app.engagement
        .planning_picker_mut()
        .open(vec![row], [task].into_iter().collect());
    app.engagement
        .planning_picker_mut()
        .set_focus(PickerFocus::OptionsPane);
    app.engagement
        .planning_picker_mut()
        .set_return_to_setup(setup);
    app.set_shell_view(if setup {
        ShellView::Setup
    } else {
        ShellView::PlanningPicker
    });
    if setup {
        app.router.setup_mut().begin_editor(SetupEditor::Plan);
    }
    app.engagement
        .planning_picker_mut()
        .set_option_edit(Some(PlanningOptionEdit::new(task, name, draft)));
    app.set_input("retained shell draft");
    app
}

fn press(app: &mut ShellApp, code: KeyCode, modifiers: KeyModifiers) {
    let update = app.reduce_key(KeyEvent::new(code, modifiers));
    assert!(update.handled && update.effects.is_empty());
    assert_eq!(app.input(), "retained shell draft");
    assert!(!app.has_running_work());
}

fn draft(app: &ShellApp) -> &str {
    app.engagement
        .planning_picker()
        .option_edit()
        .unwrap()
        .field
        .text()
}

#[test]
fn planning_option_cursor_insertion_delete_and_cancel_preserve_plan() {
    for setup in [false, true] {
        let mut app = editor("sampleLimit", "200", setup);
        let selected = app.engagement.planning_picker().selected().clone();
        press(&mut app, KeyCode::Left, KeyModifiers::NONE);
        press(&mut app, KeyCode::Char('9'), KeyModifiers::NONE);
        assert_eq!(draft(&app), "2090");
        press(&mut app, KeyCode::Delete, KeyModifiers::NONE);
        assert_eq!(draft(&app), "209");
        press(&mut app, KeyCode::Home, KeyModifiers::NONE);
        press(&mut app, KeyCode::Delete, KeyModifiers::NONE);
        assert_eq!(draft(&app), "09");
        press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(app.engagement.planning_picker().option_edit().is_none());
        assert_eq!(app.engagement.planning_picker().selected(), &selected);
        assert_eq!(
            app.planning_override_count(PlanningTaskId::GatherRepoContext),
            0
        );
    }
}

#[test]
fn planning_option_editing_chords_and_save_do_not_dispatch_or_persist() {
    let mut app = editor("sampleLimit", "200", true);
    press(&mut app, KeyCode::Char('a'), KeyModifiers::CONTROL);
    press(&mut app, KeyCode::Char('k'), KeyModifiers::CONTROL);
    assert_eq!(draft(&app), "");
    let update = app.reduce_paste("7");
    assert!(update.handled && update.effects.is_empty());
    press(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
    assert!(app.engagement.planning_picker().option_edit().is_none());
    assert_eq!(
        app.resolved_input_for_planning_task(PlanningTaskId::GatherRepoContext)
            .unwrap()["sampleLimit"],
        7
    );
    let spec = app
        .planning_option_spec(PlanningTaskId::GatherRepoContext, "sampleLimit")
        .unwrap();
    assert_eq!(
        app.planning_option_stored_scope("context:build", &spec),
        None
    );
}

#[test]
fn planning_option_paste_and_shifted_multiline_input_keep_the_cursor() {
    let mut app = editor("scope", "alpha omega", false);
    press(&mut app, KeyCode::Left, KeyModifiers::ALT);
    let update = app.reduce_paste("東京\n");
    assert!(update.handled && update.effects.is_empty());
    press(&mut app, KeyCode::Char('X'), KeyModifiers::SHIFT);
    press(&mut app, KeyCode::Enter, KeyModifiers::SHIFT);
    assert_eq!(draft(&app), "alpha 東京\nX\nomega");
    press(&mut app, KeyCode::Char('q'), KeyModifiers::CONTROL);
    assert_eq!(draft(&app), "alpha 東京\nX\nomega");
    press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
}

#[test]
fn invalid_planning_option_retains_exact_draft_until_corrected() {
    let mut app = editor("sampleLimit", "200x", true);
    press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(draft(&app), "200x");
    assert!(app.engagement.planning_picker().option_error().is_some());
    assert_eq!(
        app.planning_override_count(PlanningTaskId::GatherRepoContext),
        0
    );
    press(&mut app, KeyCode::Backspace, KeyModifiers::NONE);
    press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    assert!(app.engagement.planning_picker().option_edit().is_none());
    assert_eq!(
        app.resolved_input_for_planning_task(PlanningTaskId::GatherRepoContext)
            .unwrap()["sampleLimit"],
        200
    );
}

#[test]
fn missing_planning_option_preserves_its_draft_and_explains_the_error() {
    let mut app = editor("option-removed-after-opening", "retained value", true);
    press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(draft(&app), "retained value");
    assert_eq!(
        app.engagement.planning_picker().option_error(),
        Some("selected option disappeared")
    );
}

mod rendering;

#[test]
fn planning_option_quit_chords_restore_the_exact_field_and_selection() {
    for ch in ['c', 'd'] {
        let mut app = editor("sampleLimit", "200", true);
        press(&mut app, KeyCode::Left, KeyModifiers::NONE);
        let field = app.engagement.planning_picker().option_edit().cloned();
        let selected = app.engagement.planning_picker().selected().clone();
        press(&mut app, KeyCode::Char(ch), KeyModifiers::CONTROL);
        assert_eq!(app.shell_view(), ShellView::QuitConfirm);
        assert!(!app.should_quit());
        press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(app.shell_view(), ShellView::Setup);
        assert_eq!(app.router.setup().editor(), Some(SetupEditor::Plan));
        assert_eq!(
            app.engagement.planning_picker().option_edit(),
            field.as_ref()
        );
        assert_eq!(app.engagement.planning_picker().selected(), &selected);
    }
}

#[test]
fn hidden_planning_draft_does_not_capture_another_setup_editors_paste() {
    let mut app = editor("sampleLimit", "200", true);
    app.router.setup_mut().begin_budget_edit(None);
    app.reduce_paste("9");
    assert_eq!(app.router.setup().budget_draft(), "9");
    assert_eq!(draft(&app), "200");
}
