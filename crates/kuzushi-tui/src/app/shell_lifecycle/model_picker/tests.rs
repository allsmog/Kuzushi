use crate::app::state_transitions::InputUpdate;
use crate::app::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::V2Config;

fn config_app() -> ShellApp {
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-5.5".into());
    let mut app = ShellApp::new(config, None);
    app.set_shell_view(ShellView::Tools);
    app.sync_view_change();
    app.set_shell_view(ShellView::Config);
    app.sync_view_change();
    app.set_input_mode(InputMode::Navigate);
    app
}

fn key(app: &mut ShellApp, code: KeyCode) -> InputUpdate {
    let result = app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE));
    app.sync_view_change();
    result
}

#[test]
fn config_picker_arrows_scroll_without_selecting_a_model() {
    let mut app = config_app();
    let result = key(&mut app, KeyCode::Down);
    assert!(result.handled);
    assert!(result.effects.is_empty());
    assert_eq!(app.router.default_scroll().offset(), 1);
    assert_eq!(app.config().model.as_deref(), Some("openai:gpt-5.5"));
    key(&mut app, KeyCode::Up);
    assert_eq!(app.router.default_scroll().offset(), 0);
}

#[test]
fn config_picker_enter_opens_visible_chooser_before_any_model_change() {
    let mut app = config_app();
    let result = key(&mut app, KeyCode::Enter);
    assert!(result.handled);
    assert!(result.effects.is_empty());
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert_eq!(app.router.setup().editor(), Some(SetupEditor::Model));
    assert_eq!(
        app.router.model_picker().selected_id(),
        Some("openai:gpt-5.5")
    );
    assert_eq!(app.config().model.as_deref(), Some("openai:gpt-5.5"));
}

#[test]
fn config_picker_cancel_restores_scroll_mode_drafts_phase_and_back_history() {
    let target = tempfile::tempdir().unwrap();
    let mut app = config_app();
    app.set_target(Some(target.path().into()));
    app.set_input("held shell draft");
    app.router
        .answers_mut()
        .draft
        .insert("held question α\nsecond line");
    let draft = app.router.answers().draft.clone();
    app.router.default_scroll_mut().set(17);
    app.engagement.set_phase(WorkflowPhase::Scan);
    let navigation = app.router.navigation().clone();
    app.open_model_picker();
    app.sync_view_change();
    let result = key(&mut app, KeyCode::Esc);
    assert!(result.effects.is_empty());
    assert_eq!(app.shell_view(), ShellView::Config);
    assert_eq!(app.router.default_scroll().offset(), 17);
    assert_eq!(app.input_mode(), InputMode::Navigate);
    assert_eq!(app.input(), "held shell draft");
    assert_eq!(app.router.answers().draft, draft);
    assert_eq!(app.target(), Some(target.path()));
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Scan));
    assert_eq!(app.router.navigation(), &navigation);
    app.go_back();
    assert_eq!(app.shell_view(), ShellView::Tools);
}

#[test]
fn config_picker_explicit_acceptance_applies_visible_identity_once_and_returns() {
    let mut app = config_app();
    app.router.default_scroll_mut().set(9);
    app.engagement.set_phase(WorkflowPhase::Review);
    app.open_model_picker();
    app.sync_view_change();
    key(&mut app, KeyCode::Down);
    let expected = app.router.model_picker().selected_id().unwrap().to_string();
    let result = key(&mut app, KeyCode::Enter);
    assert_eq!(app.config().model.as_deref(), Some(expected.as_str()));
    assert!(
        matches!(result.effects.as_slice(), [ShellEffect::PersistGlobalModelSelection(selection)] if selection.model == expected)
    );
    assert_eq!(app.shell_view(), ShellView::Config);
    assert_eq!(app.router.default_scroll().offset(), 9);
    assert_eq!(app.router.setup().editor(), None);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Review));
}

#[test]
fn config_picker_back_command_returns_once_without_polluting_history() {
    let mut app = config_app();
    app.router.default_scroll_mut().set(8);
    app.open_model_picker();
    app.sync_view_change();
    app.go_back();
    app.sync_view_change();
    assert_eq!(app.shell_view(), ShellView::Config);
    assert_eq!(app.router.default_scroll().offset(), 8);
    app.go_back();
    assert_eq!(app.shell_view(), ShellView::Tools);
}

#[test]
fn config_picker_reopening_keeps_the_original_config_return_state() {
    let mut app = config_app();
    app.router.default_scroll_mut().set(11);
    app.set_input_mode(InputMode::Prompt);
    app.reduce_model_command(&None);
    app.sync_view_change();
    app.reduce_model_command(&None);
    app.sync_view_change();
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Config);
    assert_eq!(app.input_mode(), InputMode::Prompt);
    assert_eq!(app.router.default_scroll().offset(), 11);
}

#[test]
fn config_picker_explicit_model_command_restores_origin_and_keeps_exact_selector() {
    let mut app = config_app();
    app.router.default_scroll_mut().set(13);
    app.open_model_picker();
    app.sync_view_change();
    let result = app.reduce_model_command(&Some("global openai-oauth:gpt-5.4 high".into()));
    app.sync_view_change();
    assert_eq!(app.config().model.as_deref(), Some("openai-codex:gpt-5.4"));
    assert_eq!(app.session_thinking_level(), Some("high"));
    assert_eq!(app.shell_view(), ShellView::Config);
    assert_eq!(app.router.default_scroll().offset(), 13);
    assert!(
        matches!(result.as_slice(), [ShellEffect::PersistGlobalModelSelection(selection)] if selection.model == "openai-codex:gpt-5.4")
    );
}

#[test]
fn config_picker_origin_does_not_leak_into_a_later_setup_editor() {
    let mut app = config_app();
    app.open_model_picker();
    key(&mut app, KeyCode::Esc);
    app.set_shell_view(ShellView::Setup);
    app.open_model_picker();
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert_eq!(app.router.setup().editor(), None);
}

#[test]
fn config_picker_prompt_enter_submits_the_command_instead_of_selecting_a_model() {
    let mut app = config_app();
    app.set_input_mode(InputMode::Prompt);
    app.set_input("help");
    let result = key(&mut app, KeyCode::Enter);
    assert_eq!(app.shell_view(), ShellView::Help);
    assert_eq!(app.config().model.as_deref(), Some("openai:gpt-5.5"));
    assert!(!result
        .effects
        .iter()
        .any(|effect| matches!(effect, ShellEffect::PersistGlobalModelSelection(_))));
}
