use super::*;
use kuzushi_core::V2Config;

#[test]
fn cap_review_requires_a_specific_amount_and_restores_the_origin() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Activity);
    app.session_mut().set_session_budget_usd(Some(0.05));
    app.record_cost(0.10);
    app.continue_past_budget();
    assert!(app.is_budget_halted());
    app.reduce_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    press(&mut app, KeyCode::Enter);
    assert!(
        app.is_budget_halted(),
        "empty input must not bypass the cap"
    );
    assert!(app.router.setup().budget_error().is_some());
    app.reduce_paste("0.2");
    assert_eq!(app.session().session_budget_usd(), Some(0.05));
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.session().session_budget_usd(), Some(0.2));
    assert!(!app.is_budget_halted());
    assert_eq!(app.shell_view(), ShellView::Activity);
}

#[test]
fn cancelling_cap_review_preserves_halt_and_origin() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Report);
    app.session_mut().set_session_budget_usd(Some(0.05));
    app.record_cost(0.10);
    app.continue_past_budget();
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!(app.session().session_budget_usd(), Some(0.05));
    assert!(app.is_budget_halted());
}

fn editing_budget(current: Option<f64>) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Setup);
    app.router.setup_mut().set_cursor(6);
    app.session_mut().set_session_budget_usd(current);
    app.router.setup_mut().begin_budget_edit(current);
    app.set_input("held shell draft");
    app
}

fn press(app: &mut ShellApp, code: KeyCode) {
    let update = app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE));
    assert!(update.handled);
    assert!(update.effects.is_empty(), "editing must not dispatch work");
}

#[test]
fn budget_editor_inserts_at_the_cursor_and_keeps_shell_draft() {
    let mut app = editing_budget(Some(12.5));
    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Char('3'));
    assert_eq!(app.router.setup().budget_draft(), "132.5");
    assert_eq!(app.session().session_budget_usd(), Some(12.5));
    assert_eq!(app.input(), "held shell draft");
}

#[test]
fn budget_editor_delete_removes_only_the_character_ahead() {
    let mut app = editing_budget(Some(12.5));
    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::Delete);
    assert_eq!(app.router.setup().budget_draft(), "2.5");
    assert_eq!(app.session().session_budget_usd(), Some(12.5));
}

#[test]
fn budget_editor_paste_inserts_at_the_cursor_without_submission() {
    let mut app = editing_budget(Some(12.5));
    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::Right);
    let update = app.reduce_paste("9");
    assert!(update.effects.is_empty());
    assert_eq!(app.router.setup().budget_draft(), "192.5");
    assert_eq!(app.session().session_budget_usd(), Some(12.5));
    assert_eq!(app.input(), "held shell draft");
}

#[test]
fn budget_editor_retains_invalid_typed_sign_instead_of_saving_another_amount() {
    let mut app = editing_budget(None);
    press(&mut app, KeyCode::Char('-'));
    press(&mut app, KeyCode::Char('5'));
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.router.setup().budget_draft(), "-5");
    assert!(app.router.setup().budget_error().is_some());
    assert_eq!(app.router.setup().editor(), Some(SetupEditor::Budget));
    assert_eq!(app.session().session_budget_usd(), None);
}

#[test]
fn budget_editor_reopening_preserves_the_saved_precision() {
    let mut app = editing_budget(Some(0.00125));
    assert_eq!(app.router.setup().budget_draft(), "0.00125");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.session().session_budget_usd(), Some(0.00125));
}

#[test]
fn budget_editor_control_u_belongs_to_the_field() {
    let mut app = editing_budget(Some(12.5));
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    assert!(update.handled);
    assert!(update.effects.is_empty());
    assert_eq!(app.router.setup().budget_draft(), "");
    assert_eq!(app.input(), "held shell draft");
}

#[test]
fn budget_editor_invalid_paste_keeps_the_prior_cap_and_complete_draft() {
    for draft in ["0", "-5", "NaN", "inf", "1e999", "$5", "2\n3", "東京"] {
        let mut app = editing_budget(Some(4.0));
        app.router.setup_mut().begin_budget_edit(None);
        assert!(app.reduce_paste(draft).effects.is_empty());
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.router.setup().budget_draft(), draft);
        assert!(app.router.setup().budget_error().is_some(), "{draft}");
        assert_eq!(app.session().session_budget_usd(), Some(4.0));
        assert_eq!(app.router.setup().editor(), Some(SetupEditor::Budget));
        assert_eq!(app.input(), "held shell draft");
    }
}

#[test]
fn budget_editor_ceiling_refusal_is_exact_and_retains_error_while_moving() {
    let mut app = editing_budget(Some(0.001));
    app.config_mut().operator.spend_hard_ceiling_usd = Some(0.00125);
    app.router.setup_mut().begin_budget_edit(None);
    app.reduce_paste("0.00126");
    press(&mut app, KeyCode::Enter);
    let error = app.router.setup().budget_error().unwrap().to_string();
    assert!(error.contains("$0.00125"));
    press(&mut app, KeyCode::Home);
    assert_eq!(app.router.setup().budget_error(), Some(error.as_str()));
    assert_eq!(app.session().session_budget_usd(), Some(0.001));
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Backspace);
    press(&mut app, KeyCode::Char('5'));
    assert_eq!(app.router.setup().budget_error(), None);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.session().session_budget_usd(), Some(0.00125));
}

#[test]
fn budget_editor_cancel_restores_setup_and_preserves_target_plan_phase_and_drafts() {
    let mut app = editing_budget(Some(8.0));
    let target = tempfile::tempdir().unwrap();
    app.set_target(Some(target.path().into()));
    app.engagement.set_phase(WorkflowPhase::Scan);
    app.router.answers_mut().draft.insert("held question α");
    let answer = app.router.answers().draft.clone();
    let plan = app.router.setup().map_run_config().clone();
    app.reduce_paste("99");
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert_eq!(app.router.setup().editor(), None);
    assert_eq!(app.router.setup().cursor(), 6);
    assert_eq!(app.router.setup().map_run_config(), &plan);
    assert_eq!(app.target(), Some(target.path()));
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Scan));
    assert_eq!(app.router.answers().draft, answer);
    assert_eq!(app.input(), "held shell draft");
    assert_eq!(app.session().session_budget_usd(), Some(8.0));
}

#[test]
fn budget_editor_empty_save_unsets_only_the_session_cap() {
    let mut app = editing_budget(Some(4.0));
    app.config_mut().operator.spend_hard_ceiling_usd = Some(10.0);
    app.config_mut().operator.session_budget_usd = Some(4.0);
    app.reduce_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
    assert!(update.effects.is_empty());
    assert_eq!(app.session().session_budget_usd(), None);
    assert_eq!(app.config().operator.spend_hard_ceiling_usd, Some(10.0));
    assert_eq!(app.config().operator.session_budget_usd, Some(4.0));
    assert_eq!(app.router.setup().editor(), None);
}

#[test]
fn budget_editor_unbound_chords_never_insert_or_save() {
    let mut app = editing_budget(Some(8.0));
    for key in [
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL),
        KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT),
        KeyEvent::new(KeyCode::Char('5'), KeyModifiers::ALT),
    ] {
        let update = app.reduce_key(key);
        assert!(update.effects.is_empty());
        assert_eq!(app.router.setup().budget_draft(), "8");
        assert_eq!(app.router.setup().editor(), Some(SetupEditor::Budget));
        assert_eq!(app.input(), "held shell draft");
    }
}

#[test]
fn budget_editor_open_takes_focus_from_a_previous_command_field() {
    let mut app = editing_budget(Some(8.0));
    app.router.setup_mut().set_focus(PickerFocus::Prompt);
    app.router.setup_mut().begin_budget_edit(Some(8.0));
    press(&mut app, KeyCode::Char('2'));
    assert_eq!(app.router.setup().budget_draft(), "82");
    assert_eq!(app.input(), "held shell draft");
    assert!(!app.picker_prompt_focused());
}

#[test]
fn budget_editor_quit_chords_disclose_then_restore_the_active_field() {
    for ch in ['c', 'd'] {
        let mut app = editing_budget(Some(4.0));
        app.reduce_paste("9");
        let update = app.reduce_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::CONTROL));
        assert!(update.effects.is_empty());
        assert_eq!(app.shell_view(), ShellView::QuitConfirm);
        assert!(!app.should_quit());
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.shell_view(), ShellView::Setup);
        assert_eq!(app.router.setup().editor(), Some(SetupEditor::Budget));
        assert_eq!(app.router.setup().budget_draft(), "49");
        assert_eq!(app.session().session_budget_usd(), Some(4.0));
        assert_eq!(app.input(), "held shell draft");
    }
}

#[test]
fn budget_editor_saved_setup_receipt_keeps_precision_and_ceiling_identity() {
    let mut app = editing_budget(Some(0.00125));
    app.router.setup_mut().finish_editor();
    let model = crate::ui_view_models::setup_readiness_model(&app);
    let budget = model
        .rows
        .iter()
        .find(|row| row.id == SetupRowId::Budget)
        .unwrap();
    assert_eq!(budget.status, "OBSERVED STOP");
    assert_eq!(
        budget.detail,
        "$0.00125 after cost receipts; charges may exceed this amount"
    );
    app.config_mut().operator.spend_hard_ceiling_usd = Some(0.00124);
    let model = crate::ui_view_models::setup_readiness_model(&app);
    let budget = model
        .rows
        .iter()
        .find(|row| row.id == SetupRowId::Budget)
        .unwrap();
    assert_eq!(budget.status, "OVER CEILING");
    assert!(budget.detail.contains("$0.00125") && budget.detail.contains("$0.00124"));
}
