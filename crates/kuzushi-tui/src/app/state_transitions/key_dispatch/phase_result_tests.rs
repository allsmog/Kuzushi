//! The RESULT READY card is where an operator accepts or rejects a phase
//! attempt, and it advertises one single-key shortcut per offered action. Every
//! other test drives those actions by calling `apply_phase_result_command`
//! directly, which skips the whole `reduce_key` chain the operator actually
//! goes through — guided-question capture, autonomy chords, keymap overrides,
//! then the phase-result branch. These tests feed real `KeyEvent`s so that a
//! key the card prints cannot silently stop reaching its action.

use super::*;
use kuzushi_core::workflow_attempts::{PhaseAttemptOutcome, PhaseResultAction};
use kuzushi_core::{V2Config, WorkflowPhase, WorkspaceTarget};

struct ResultCardFixture {
    _temp: tempfile::TempDir,
    app: ShellApp,
}

impl ResultCardFixture {
    /// A completed attempt for `phase` with its RESULT READY card open on the
    /// matching Workbench page, in Navigate mode — the state the card's
    /// single-key hints are printed in.
    fn open(phase: WorkflowPhase, tool: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        crate::test_support::record_indexed_run(
            temp.path(),
            "run-result-card",
            tool,
            serde_json::json!({
                "ok": true,
                "status": "completed",
                "data": { "snapshot": { "filesIndexed": 1 } }
            }),
        );
        crate::test_support::append_typed_attempt(
            temp.path(),
            phase,
            "run-result-card",
            PhaseAttemptOutcome::Completed,
        );
        app.refresh_phase_attempt_projection();
        app.set_shell_view(ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(WorkbenchPage::from_phase(phase)));
        app.set_input_mode(InputMode::Navigate);
        Self { _temp: temp, app }
    }

    fn advertised_actions(&self, phase: WorkflowPhase) -> Vec<PhaseResultAction> {
        crate::ui_view_models::phase_cockpit_model_for_phase(&self.app, phase)
            .header
            .result_card
            .expect("RESULT READY card")
            .actions
    }

    fn press(&mut self, key: char) -> InputUpdate {
        self.app
            .reduce_key(KeyEvent::new(KeyCode::Char(key), KeyModifiers::NONE))
    }

    fn attempt_is_unresolved(&self, phase: WorkflowPhase) -> bool {
        self.app
            .engagement
            .unresolved_phase_attempt(phase)
            .is_some()
    }

    fn notice_message(&self) -> Option<String> {
        self.app
            .advisory()
            .notice
            .as_ref()
            .map(|notice| notice.message.clone())
    }
}

fn advertised_key(command: PhaseResultCommand) -> char {
    command
        .default_hint()
        .chars()
        .next()
        .expect("every phase-result command advertises a key")
}

/// What the operator should be able to observe once the action ran. Selection
/// and discard both resolve the attempt; a rerun opens its review; `Open`
/// leaves the Workbench for the run it names.
fn action_took_effect(
    fixture: &ResultCardFixture,
    phase: WorkflowPhase,
    command: PhaseResultCommand,
) -> bool {
    match command {
        PhaseResultCommand::Select | PhaseResultCommand::Continue | PhaseResultCommand::Discard => {
            !fixture.attempt_is_unresolved(phase)
        }
        PhaseResultCommand::Refine
        | PhaseResultCommand::RunAgain
        | PhaseResultCommand::Regenerate => fixture.app.engagement.pending_phase_rerun().is_some(),
        PhaseResultCommand::Open => fixture.app.shell_view() != ShellView::Workbench,
        // Only a failed attempt offers a checkpoint to resume, so a completed
        // card never advertises this one.
        PhaseResultCommand::ContinueRun => false,
    }
}

#[test]
fn every_advertised_result_card_key_dispatches_its_action() {
    for (phase, tool) in [
        (WorkflowPhase::Map, "context:build"),
        (WorkflowPhase::Scan, "secret-scan:scan"),
        (WorkflowPhase::Review, "triage:run"),
    ] {
        let actions = ResultCardFixture::open(phase, tool).advertised_actions(phase);
        assert!(
            !actions.is_empty(),
            "{phase:?} RESULT READY card advertises no action"
        );
        for action in actions {
            let command = PhaseResultCommand::from_action(action);
            let key = advertised_key(command);
            // One fixture per key: the first action resolves the card, and a
            // resolved card cannot answer for the keys after it.
            let mut fixture = ResultCardFixture::open(phase, tool);

            let update = fixture.press(key);

            assert!(
                update.handled,
                "{phase:?} `{key}` ({action:?}) was not read"
            );
            assert!(
                action_took_effect(&fixture, phase, command),
                "{phase:?} advertises `{key}` for {action:?}, but pressing it changed nothing"
            );
        }
    }
}

#[test]
fn a_rerun_without_a_re_runnable_run_says_so_on_screen() {
    // `r` is advertised on every completed card, but an exact rerun needs a
    // referenced run that still carries a readable input for a loaded tool.
    // When none does, the operator has to be told rather than left pressing a
    // key that does nothing.
    let mut fixture = ResultCardFixture::open(WorkflowPhase::Scan, "retired-module:scan");

    fixture.press('r');

    assert!(
        fixture.app.engagement.pending_phase_rerun().is_none(),
        "a run with no re-runnable specification must not open a rerun review"
    );
    let notice = fixture
        .notice_message()
        .expect("a refused rerun must paint a notice, not only a transcript line");
    assert!(
        notice.contains("exact rerun unavailable"),
        "refusal notice should name what was refused: {notice}"
    );
}

#[test]
fn a_refused_selection_says_so_on_screen() {
    // A Fix attempt whose run carries no reviewable patch: selection is
    // refused, which is correct. What the operator must not get is silence.
    let mut fixture = ResultCardFixture::open(WorkflowPhase::Fix, "context:build");

    fixture.press('u');

    assert!(
        fixture.attempt_is_unresolved(WorkflowPhase::Fix),
        "an unvalidated Fix patch must not cross the select action"
    );
    let notice = fixture
        .notice_message()
        .expect("a refused result-card action must paint a notice, not only a transcript line");
    assert!(
        notice.contains("Fix selection blocked"),
        "refusal notice should name what was refused: {notice}"
    );
}

#[test]
fn prompt_mode_leaves_result_card_keys_to_the_composer() {
    let mut fixture = ResultCardFixture::open(WorkflowPhase::Map, "context:build");
    fixture.app.set_input_mode(InputMode::Prompt);

    fixture.press('u');

    assert_eq!(fixture.app.input(), "u");
    assert!(
        fixture.attempt_is_unresolved(WorkflowPhase::Map),
        "a composed character must not resolve the attempt behind the composer"
    );
    let hint =
        crate::ui_view_models::phase_cockpit_model_for_phase(&fixture.app, WorkflowPhase::Map)
            .header
            .result_card
            .expect("RESULT READY card")
            .control_hint;
    assert!(
        hint.contains("Navigate"),
        "Prompt mode must advertise the way back to the card's keys, not the keys: {hint}"
    );
}

#[test]
fn an_unadvertised_default_key_leaves_the_card_alone() {
    // Prove withholds Discard: a proof set is discarded by rejecting its
    // findings, not by dropping the attempt. `d` is still a phase-result
    // default, so it must land as a no-op rather than a hidden disposition.
    let mut fixture = ResultCardFixture::open(WorkflowPhase::Prove, "context:build");
    assert!(!fixture
        .advertised_actions(WorkflowPhase::Prove)
        .contains(&PhaseResultAction::Discard));

    fixture.press('d');

    assert!(
        fixture.attempt_is_unresolved(WorkflowPhase::Prove),
        "an unadvertised key must not resolve the attempt"
    );
    assert_eq!(
        fixture.notice_message(),
        None,
        "an unadvertised key must not claim a receipt either"
    );
}
