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

mod frozen_map;
mod scan_reading;

#[test]
fn review_result_controls_name_report_and_own_their_footer_keys() {
    let mut fixture = review_continuation_fixture(false);
    let hint = review_result_hint(&fixture.app);
    assert!(hint.contains("Report"), "{hint}");
    assert!(!hint.contains("Prove"), "{hint}");
    let bindings = crate::ui_view_models::footer_keybindings(&fixture.app);
    assert!(
        bindings
            .iter()
            .any(|binding| binding.key == "n" && binding.label.contains("Report")),
        "{bindings:?}"
    );
    assert!(
        !bindings.iter().any(|binding| binding.key == "n/N"),
        "{bindings:?}"
    );
    fixture.press('n');
    assert_eq!(fixture.app.shell_view(), ShellView::Report);
    assert!(!fixture.attempt_is_unresolved(WorkflowPhase::Review));
}

#[test]
fn actionable_review_controls_and_key_reducer_agree_on_report() {
    let mut fixture = review_continuation_fixture(true);
    assert!(review_result_hint(&fixture.app).contains("Report"));
    fixture.press('n');
    assert_eq!(fixture.app.shell_view(), ShellView::Report);
    assert!(!fixture.attempt_is_unresolved(WorkflowPhase::Review));
}

#[test]
fn review_continuation_respects_an_earlier_unresolved_phase() {
    let mut fixture = review_continuation_fixture(false);
    crate::test_support::record_indexed_run(
        fixture._temp.path(),
        "new-map",
        "threat-model:build",
        serde_json::json!({"ok": true, "data": {"snapshot": {"filesIndexed": 1}}}),
    );
    crate::test_support::append_typed_attempt(
        fixture._temp.path(),
        WorkflowPhase::Map,
        "new-map",
        PhaseAttemptOutcome::Completed,
    );
    fixture.app.refresh_phase_attempt_projection();
    let hint = review_result_hint(&fixture.app);
    assert!(hint.contains("Use & Map"), "{hint}");
    assert!(!hint.contains("Use & Report"), "{hint}");
    fixture.press('n');
    assert_eq!(fixture.app.shell_view(), ShellView::Workbench);
    assert_eq!(
        crate::ui_view_models::active_workbench_page(&fixture.app),
        WorkbenchPage::Map
    );
    assert!(fixture.attempt_is_unresolved(WorkflowPhase::Map));
    assert!(!fixture.attempt_is_unresolved(WorkflowPhase::Review));
}

fn review_continuation_fixture(actionable: bool) -> ResultCardFixture {
    let mut fixture = ResultCardFixture::open(WorkflowPhase::Review, "triage:run");
    for phase in [WorkflowPhase::Map, WorkflowPhase::Scan] {
        seed_selected_phase(fixture._temp.path(), phase);
    }
    seed_reviewed_finding(fixture._temp.path(), actionable);
    fixture.app.refresh_phase_attempt_projection();
    fixture.app.refresh_findings(false);
    fixture
}

fn seed_selected_phase(target: &std::path::Path, phase: WorkflowPhase) {
    use kuzushi_core::workflow_attempts::{
        append_phase_attempt_disposition, PhaseAttemptDisposition, PhaseAttemptDispositionRecorded,
    };
    let run_id = format!("accepted-{phase:?}").to_lowercase();
    crate::test_support::record_indexed_run(
        target,
        &run_id,
        match phase {
            WorkflowPhase::Map => "threat-model:build",
            WorkflowPhase::Scan => "secret-scan:scan",
            _ => unreachable!(),
        },
        serde_json::json!({"ok":true,"data":{"snapshot":{"filesIndexed":1}}}),
    );
    let completed = crate::test_support::append_typed_attempt(
        target,
        phase,
        &run_id,
        PhaseAttemptOutcome::Completed,
    );
    append_phase_attempt_disposition(
        target,
        PhaseAttemptDispositionRecorded::new(
            completed.attempt_id,
            PhaseAttemptDisposition::Selected {
                acknowledged_partial: false,
            },
        ),
    )
    .unwrap();
}

fn seed_reviewed_finding(target: &std::path::Path, actionable: bool) {
    let workspace = WorkspaceTarget::new(target).unwrap();
    let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
    let finding = kuzushi_core::Finding::new_tool(
        "audit",
        "rule",
        "lib.rs",
        1,
        None,
        kuzushi_core::Severity::Medium,
        "reviewed candidate",
    );
    let id = store.insert_finding("accepted-scan", &finding).unwrap();
    let outcome = kuzushi_core::TriageOutcome {
        verdict: if actionable {
            kuzushi_core::TriageVerdict::TruePositive
        } else {
            kuzushi_core::TriageVerdict::FalsePositive
        },
        confidence: 0.9,
        rationale: "recorded review decision".to_string(),
        ..Default::default()
    };
    if actionable {
        store
            .record_triage_with_author(id, &outcome, kuzushi_core::findings::TriageAuthor::Human)
            .unwrap();
    } else {
        store.record_auto_triage_locally(id, &outcome).unwrap();
    }
}

fn review_result_hint(app: &ShellApp) -> String {
    crate::ui_view_models::phase_cockpit_model_for_phase(app, WorkflowPhase::Review)
        .header
        .result_card
        .expect("pending Review result")
        .control_hint
}

struct ResultCardFixture {
    _temp: tempfile::TempDir,
    app: ShellApp,
}

#[test]
fn pending_scan_reading_pages_without_accepting_or_changing_the_draft() {
    use crate::ui_view_models::PhaseSurfaceId;
    let mut fixture = ResultCardFixture::open(WorkflowPhase::Scan, "sast:scan");
    fixture
        .app
        .set_viewport(crate::TerminalViewport::new(40, 12));
    fixture.app.editor_mut().set_input("keep this draft");
    let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
    assert!(fixture.app.reduce_key(key(KeyCode::PageDown)).handled);
    let offset = fixture
        .app
        .router
        .workbench()
        .scroll()
        .get(PhaseSurfaceId::ScanEngines);
    assert!(
        offset > 0,
        "advertised paging must reach engine evidence; limit {:?}; body {:?}",
        crate::renderer::workbench_scroll_metrics(&fixture.app),
        crate::ui_view_models::phase_cockpit_model_for_phase(&fixture.app, WorkflowPhase::Scan)
            .body
    );
    assert!(fixture.app.reduce_key(key(KeyCode::PageUp)).handled);
    assert_eq!(
        fixture
            .app
            .router
            .workbench()
            .scroll()
            .get(PhaseSurfaceId::ScanEngines),
        0
    );
    assert!(fixture.attempt_is_unresolved(WorkflowPhase::Scan));
    assert_eq!(fixture.app.input(), "keep this draft");
    assert_eq!(fixture.app.input_mode(), InputMode::Navigate);
}

impl ResultCardFixture {
    /// A completed attempt for `phase` with its RESULT READY card open on the
    /// matching Workbench page, in Navigate mode — the state the card's
    /// single-key hints are printed in.
    fn open(phase: WorkflowPhase, tool: &str) -> Self {
        let input = if tool == "threat-model:build" {
            serde_json::json!({"pipeline":"deterministic","offline":true,"variantScan":false})
        } else {
            serde_json::json!({})
        };
        Self::open_with_input(phase, tool, input)
    }

    fn open_with_input(phase: WorkflowPhase, tool: &str, input: Value) -> Self {
        Self::open_with_outcome(phase, tool, input, PhaseAttemptOutcome::Completed)
    }

    fn open_with_outcome(
        phase: WorkflowPhase,
        tool: &str,
        input: Value,
        outcome: PhaseAttemptOutcome,
    ) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        crate::test_support::record_indexed_run_with_input(
            temp.path(),
            "run-result-card",
            tool,
            input,
            serde_json::json!({
                "ok": outcome == PhaseAttemptOutcome::Completed,
                "status": outcome,
                "data": if phase == WorkflowPhase::Scan {
                    scan_reading::scan_result_data(temp.path())
                } else {
                    serde_json::json!({ "snapshot": { "filesIndexed": 1 } })
                }
            }),
        );
        crate::test_support::append_typed_attempt(temp.path(), phase, "run-result-card", outcome);
        app.refresh_phase_attempt_projection();
        if phase == WorkflowPhase::Scan {
            app.hydrate_view_keys_blocking(
                workspace.root(),
                vec![
                    ViewHydrationKey::RunSummaryEntries,
                    ViewHydrationKey::ScanStageReceipt {
                        run_id: "run-result-card".into(),
                    },
                ],
            );
        }
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
        (WorkflowPhase::Map, "threat-model:build"),
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
    let mut fixture = ResultCardFixture::open(WorkflowPhase::Fix, "fixture:legacy-result");

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
    let mut fixture = ResultCardFixture::open(WorkflowPhase::Map, "threat-model:build");
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
    let mut fixture = ResultCardFixture::open(WorkflowPhase::Prove, "fixture:legacy-result");
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

#[test]
fn threat_model_refine_review_discloses_and_dispatches_canonical_override() {
    assert_threat_model_action_review(
        'f',
        serde_json::json!({"mode": "build", "seedMode": "seeded"}),
        &[("mode", "refine")],
    );
}

#[test]
fn threat_model_regenerate_review_discloses_and_dispatches_canonical_overrides() {
    assert_threat_model_action_review(
        'g',
        serde_json::json!({"mode": "refine", "seedMode": "seeded"}),
        &[("mode", "build"), ("seedMode", "fresh")],
    );
}

#[test]
fn threat_model_rerun_refuses_input_that_changed_after_review() {
    let mut fixture = ResultCardFixture::open_with_input(
        WorkflowPhase::Map,
        "threat-model:build",
        serde_json::json!({"mode": "build", "seedMode": "seeded"}),
    );
    assert!(fixture.press('f').handled);
    let prompt_dir = fixture._temp.path().join(".kuzushi/prompts/threat-model");
    std::fs::create_dir_all(&prompt_dir).unwrap();
    std::fs::write(prompt_dir.join("build.md"), "new operator guidance").unwrap();

    let update = fixture
        .app
        .reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

    assert!(update.effects.is_empty(), "changed input must not dispatch");
    let notice = fixture
        .notice_message()
        .expect("changed preparation must be refused on screen");
    assert!(notice.contains("input changed after review"), "{notice}");
}

fn assert_threat_model_action_review(key: char, saved_input: Value, expected: &[(&str, &str)]) {
    let mut fixture =
        ResultCardFixture::open_with_input(WorkflowPhase::Map, "threat-model:build", saved_input);

    assert!(fixture.press(key).handled);
    let reviewed_input = match fixture.app.engagement.pending_phase_rerun() {
        Some(review) => review.prepared_input.clone(),
        None => panic!(
            "action did not open a rerun review: {:?}",
            fixture.notice_message()
        ),
    };
    let card =
        crate::ui_view_models::phase_cockpit_model_for_phase(&fixture.app, WorkflowPhase::Map)
            .header
            .result_card
            .expect("rerun review card");
    let plain = crate::renderer::render_plain_app(&fixture.app, 120);
    for (name, value) in expected {
        assert_eq!(reviewed_input[*name], serde_json::json!(value));
        let disclosed = format!("{name} = {value}");
        assert!(card.detail.contains(&disclosed), "{}", card.detail);
        assert!(plain.contains(&disclosed), "{plain}");
    }

    let update = fixture
        .app
        .reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    let [ShellEffect::DispatchRunTool(launch)] = update.effects.as_slice() else {
        panic!("expected reviewed threat-model rerun dispatch");
    };
    assert_eq!(launch.input.value(), &reviewed_input);
}

#[test]
fn phase_rerun_action_overrides_are_narrowly_scoped() {
    use kuzushi_core::workflow_attempts::PhaseAttemptDerivation::{Original, Refine, Regenerate};

    assert_eq!(
        phase_rerun_action_overrides(Some(Refine), "threat-model:build"),
        &[("mode", "refine")]
    );
    assert_eq!(
        phase_rerun_action_overrides(Some(Regenerate), "threat-model:build"),
        &[("mode", "build"), ("seedMode", "fresh")]
    );
    assert!(phase_rerun_action_overrides(None, "threat-model:build").is_empty());
    assert!(phase_rerun_action_overrides(Some(Original), "threat-model:build").is_empty());
    assert!(phase_rerun_action_overrides(Some(Refine), "context:build").is_empty());
    assert!(phase_rerun_action_overrides(Some(Regenerate), "context:build").is_empty());
}

// ── Navigate never types a result-card key (issue #172 key-dispatch race) ──

#[test]
fn repeated_card_key_after_resolution_is_absorbed_not_typed() {
    let mut fixture = ResultCardFixture::open(WorkflowPhase::Map, "threat-model:build");

    for _ in 0..5 {
        assert!(fixture.press('u').handled);
    }

    assert!(!fixture.attempt_is_unresolved(WorkflowPhase::Map));
    assert_eq!(
        fixture.app.input(),
        "",
        "stale re-presses must not become a draft"
    );
    assert_eq!(fixture.app.input_mode(), InputMode::Navigate);
    let notice = fixture.notice_message().unwrap_or_default();
    assert!(notice.contains("already resolved"), "{notice}");
}

#[test]
fn another_key_ends_the_resolved_key_echo_window() {
    let mut fixture = ResultCardFixture::open(WorkflowPhase::Map, "threat-model:build");
    fixture.press('u');
    assert_eq!(fixture.app.editor().resolved_result_key(), Some('u'));

    fixture
        .app
        .reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));

    assert_eq!(fixture.app.editor().resolved_result_key(), None);
}

#[test]
fn stray_card_letters_from_an_earlier_race_are_dropped_on_resolution() {
    let mut fixture = ResultCardFixture::open(WorkflowPhase::Scan, "secret-scan:scan");
    fixture.app.editor_mut().set_input("uu");

    // Exercise settlement after an explicit disposition, independently of the draft-owning keyboard gate.
    assert!(
        fixture
            .app
            .apply_phase_result_command(PhaseResultCommand::Select)
            .handled
    );
    fixture
        .app
        .settle_claimed_phase_result_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::NONE));

    assert!(
        !fixture.attempt_is_unresolved(WorkflowPhase::Scan),
        "notice={:?} mode={:?} actions={:?}",
        fixture.notice_message(),
        fixture.app.input_mode(),
        fixture.advertised_actions(WorkflowPhase::Scan)
    );
    assert_eq!(fixture.app.input(), "");
}

#[test]
fn a_real_draft_survives_result_resolution() {
    let mut fixture = ResultCardFixture::open(WorkflowPhase::Scan, "secret-scan:scan");
    fixture.app.editor_mut().set_input("scan src/");

    // Exercise settlement after an explicit disposition, independently of the draft-owning keyboard gate.
    assert!(
        fixture
            .app
            .apply_phase_result_command(PhaseResultCommand::Select)
            .handled
    );
    fixture
        .app
        .settle_claimed_phase_result_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::NONE));

    assert!(
        !fixture.attempt_is_unresolved(WorkflowPhase::Scan),
        "notice={:?} mode={:?} actions={:?}",
        fixture.notice_message(),
        fixture.app.input_mode(),
        fixture.advertised_actions(WorkflowPhase::Scan)
    );
    assert_eq!(fixture.app.input(), "scan src/");
}

#[test]
fn card_key_off_the_workbench_reveals_the_card_without_applying_it() {
    let mut fixture = ResultCardFixture::open(WorkflowPhase::Map, "threat-model:build");
    fixture.app.set_shell_view(ShellView::Activity);
    fixture.app.set_input_mode(InputMode::Navigate);

    assert!(fixture.press('u').handled);

    assert_eq!(fixture.app.shell_view(), ShellView::Workbench);
    assert_eq!(
        crate::ui_view_models::active_workbench_page(&fixture.app),
        WorkbenchPage::Map
    );
    assert!(
        fixture.attempt_is_unresolved(WorkflowPhase::Map),
        "an unseen card must not be resolved by the key that reveals it"
    );
    assert_eq!(fixture.app.input(), "");
    assert_eq!(fixture.app.input_mode(), InputMode::Navigate);
    let notice = fixture.notice_message().unwrap_or_default();
    assert!(notice.contains("press u again"), "{notice}");

    fixture.press('u');
    assert!(!fixture.attempt_is_unresolved(WorkflowPhase::Map));
    assert!(
        fixture.notice_message().is_none(),
        "the reveal notice is stale once the card is resolved"
    );
}

#[test]
fn footer_esc_names_notice_dismissal_while_a_warning_holds_escape() {
    let mut fixture = ResultCardFixture::open(WorkflowPhase::Map, "threat-model:build");
    fixture.press('u');
    fixture.app.set_warn_notice("run", "partial receipt");

    let bindings = crate::ui_view_models::footer_keybindings(&fixture.app);

    assert!(
        bindings
            .iter()
            .any(|binding| binding.key == "Esc" && binding.label == "dismiss notice"),
        "{bindings:?}"
    );
    fixture
        .app
        .reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(fixture.app.input_mode(), InputMode::Navigate);
    assert!(fixture.notice_message().is_none());
}

#[test]
fn pending_guided_results_keep_coverage_paging_and_the_composer_draft() {
    use crate::ui_view_models::PhaseSurfaceId;
    for outcome in [
        PhaseAttemptOutcome::Completed,
        PhaseAttemptOutcome::Partial,
        PhaseAttemptOutcome::Failed,
        PhaseAttemptOutcome::Canceled,
    ] {
        let mut fixture = pending_guided_scan_fixture(outcome);
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(fixture.app.reduce_key(key(KeyCode::PageDown)).handled);
        assert!(
            fixture
                .app
                .router
                .workbench()
                .scroll()
                .get(PhaseSurfaceId::ScanEngines)
                > 0,
            "{outcome:?} result swallowed coverage paging"
        );
        assert!(fixture.app.reduce_key(key(KeyCode::PageUp)).handled);
        assert_eq!(
            fixture
                .app
                .router
                .workbench()
                .scroll()
                .get(PhaseSurfaceId::ScanEngines),
            0
        );
        assert!(fixture.attempt_is_unresolved(WorkflowPhase::Scan));
        assert_eq!(fixture.app.input(), "keep this draft");
        assert_eq!(fixture.app.input_mode(), InputMode::Navigate);
    }
}

fn pending_guided_scan_fixture(outcome: PhaseAttemptOutcome) -> ResultCardFixture {
    use crate::app::guided_scan::{GuidedScanFlow, GuidedScanStage};
    let mut fixture = ResultCardFixture::open_with_outcome(
        WorkflowPhase::Scan,
        "sast:scan",
        serde_json::json!({}),
        outcome,
    );
    fixture
        .app
        .set_viewport(crate::TerminalViewport::new(40, 12));
    fixture.app.editor_mut().set_input("keep this draft");
    let attempt = fixture
        .app
        .engagement
        .unresolved_phase_attempt(WorkflowPhase::Scan)
        .unwrap()
        .completed
        .attempt_id
        .clone();
    fixture
        .app
        .engagement
        .set_guided_scan(GuidedScanFlow::new(GuidedScanStage::AwaitingResult {
            phase: WorkflowPhase::Scan,
            attempt_id: attempt,
        }));
    assert_eq!(
        fixture.app.guided_scan_question_is_open(),
        outcome != PhaseAttemptOutcome::Completed
    );
    fixture
}
