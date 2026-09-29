use super::*;

fn completed_map_from_prompt() -> (tempfile::TempDir, ShellApp) {
    let (target, mut app) = completed_map();
    app.activity_mut()
        .unwrap()
        .run_focus_origin
        .as_mut()
        .unwrap()
        .input_mode = InputMode::Prompt;
    (target, app)
}

fn press(app: &mut ShellApp, ch: char) {
    app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char(ch),
        crossterm::event::KeyModifiers::NONE,
    ));
}

#[test]
fn completed_setup_map_leaves_a_focused_answers_deck_owning_its_keys() {
    let (_target, mut app) = completed_map_from_prompt();
    app.open_answers();
    assert!(crate::ui_view_models::answers_own_input(&app));

    assert!(app.finalize_run_focus_if_idle());

    // `handle_answer_key` consumes printables ahead of card dispatch while
    // the deck owns input, so arming here would advertise keys it eats.
    assert_eq!(app.input_mode(), InputMode::Prompt);
    press(&mut app, 'u');
    assert_eq!(app.router.answers().draft.text(), "u");
    assert_eq!(app.input(), "");
    assert!(app
        .engagement
        .selected_phase_attempt(WorkflowPhase::Map)
        .is_none());
}

#[test]
fn completed_setup_map_never_turns_a_steer_draft_into_card_actions() {
    let (_target, mut app) = completed_map_from_prompt();
    app.router.activity_mut().open_steer_editor();
    app.router
        .activity_mut()
        .steer_editor
        .as_mut()
        .unwrap()
        .input = "run sast:scan".into();

    assert!(app.finalize_run_focus_if_idle());

    // The operator was mid-typing when the run ended; the keys they are still
    // pressing must not become Select or Discard decisions on the card.
    assert_eq!(app.input_mode(), InputMode::Prompt);
    press(&mut app, 'u');
    press(&mut app, 'd');
    assert!(app
        .engagement
        .selected_phase_attempt(WorkflowPhase::Map)
        .is_none());
    assert!(app
        .engagement
        .unresolved_phase_attempt(WorkflowPhase::Map)
        .is_some());
}
