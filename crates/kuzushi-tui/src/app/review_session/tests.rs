//! Review-session recording, and the invariant that makes it safe to ship:
//! the queue the operator sees is identical with recording on or off.

use super::*;
use crate::app::update::{update, Msg};
use crate::commands::{ReviewDecisionCommand, ShellCommand};
use crate::ui_view_models::{
    baseline_sorted_finding_alias_indices, review_yield_detail_for,
    visible_sorted_finding_alias_indices, PhaseSurfaceId, ReviewQueueMode, ReviewYieldDetailModel,
};

mod learn;
mod proactive_scoring;
mod within_band;
use crate::TermEvent;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::findings::{FindingStore, Severity};
use kuzushi_core::{ReviewYieldConfig, ReviewYieldMode, V2Config, WorkspaceTarget};

/// A committed artifact, so arming a mode in a test goes through the same
/// fail-closed loader an operator does.
fn shadow_model_path() -> std::path::PathBuf {
    std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../experiments/review-yield/fixtures/parity/model-mixed-depth3.json"
    ))
}

fn queue_finding(index: usize, severity: Severity) -> Finding {
    let mut finding = Finding::new_semgrep(
        "demo.rule",
        "src/app.ts",
        8,
        Some(8),
        severity,
        "dangerous sink",
    );
    finding.fingerprint = format!("fp-{index:04}");
    finding
}

/// Arms review yield the way an operator does: through the `[review_yield]`
/// section of the operator-owned config, not a flag.
fn arm_from_config(app: &mut ShellApp, mode: ReviewYieldMode, model_path: std::path::PathBuf) {
    app.config_mut().review_yield = ReviewYieldConfig {
        mode,
        model_path: Some(model_path),
    };
    app.apply_review_yield_config();
}

struct Harness {
    _temp: tempfile::TempDir,
    workspace: WorkspaceTarget,
    app: ShellApp,
}

/// A shell parked on the review queue of a real target, with a read cutoff
/// already known. Shadow recording is still off: each test arms it explicitly.
fn harness(count: usize) -> Harness {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_target(Some(workspace.root().to_path_buf()));
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ReviewQueue);
    app.set_input_mode(crate::InputMode::Navigate);
    app.set_findings(
        (0..count)
            .map(|index| queue_finding(index, Severity::High))
            .collect(),
    );
    app.router.findings_mut().set_cursor(0);
    app.set_findings_read_watermark(Some(12_000));
    Harness {
        _temp: temp,
        workspace,
        app,
    }
}

impl Harness {
    fn arm(&mut self) {
        self.arm_in(ReviewYieldMode::Shadow);
    }

    fn arm_in(&mut self, mode: ReviewYieldMode) {
        arm_from_config(&mut self.app, mode, shadow_model_path());
        assert!(
            self.app.runtime_state.review_yield().model().is_some(),
            "the committed parity artifact must load"
        );
    }

    fn press(&mut self, code: KeyCode) -> Vec<ShellEffect> {
        update(
            &mut self.app,
            Msg::Term(TermEvent::Key(KeyEvent::new(code, KeyModifiers::empty()))),
        )
        .effects
    }
}

fn session_starts(effects: &[ShellEffect]) -> Vec<&ReviewSessionApply> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            ShellEffect::RecordReviewSessionStart(apply) => Some(apply),
            _ => None,
        })
        .collect()
}

fn one_session_start(effects: &[ShellEffect]) -> &ReviewSessionApply {
    let starts = session_starts(effects);
    assert_eq!(starts.len(), 1, "expected exactly one session start");
    starts[0]
}

// ------------------------------------------------------------ what starts one

/// Moving the cursor is not review. A session that started on every keypress
/// would record dozens of openings the reviewer never made.
#[test]
fn cursor_movement_never_emits_review_session_effect() {
    let mut harness = harness(5);
    harness.arm();

    for code in [KeyCode::Down, KeyCode::Down, KeyCode::Up, KeyCode::Home] {
        let effects = harness.press(code);
        assert!(
            session_starts(&effects).is_empty(),
            "{code:?} started a review session"
        );
    }

    let finding = harness.app.findings()[0].clone();
    assert_eq!(harness.app.open_review_session_id(&finding), None);
}

#[test]
fn enter_on_review_queue_emits_one_session_effect() {
    let mut harness = harness(5);
    harness.arm();
    harness.app.router.findings_mut().set_cursor(2);
    let opened = harness.app.findings()[2].fingerprint.clone();

    let effects = harness.press(KeyCode::Enter);

    let apply = one_session_start(&effects);
    assert_eq!(apply.finding.fingerprint, opened);
    assert_eq!(apply.queue.len(), 5);
    assert_eq!(apply.baseline_index, 2);
    assert_eq!(apply.feature_cutoff_seq, 12_000);
    assert_eq!(apply.queue[apply.baseline_index].stable_fp, opened);
    assert!(!apply.review_session_id.is_empty());
}

/// Re-opening a finding the reviewer never decided on is the same sitting.
/// A second event would double-count it.
#[test]
fn reopening_same_finding_reuses_session_without_second_event() {
    let mut harness = harness(3);
    harness.arm();

    let first = harness.press(KeyCode::Enter);
    let session_id = one_session_start(&first).review_session_id.clone();
    let finding = harness.app.findings()[0].clone();

    // Back to the queue, then open the same row again.
    harness
        .app
        .router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    harness
        .app
        .router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ReviewQueue);
    let second = harness.press(KeyCode::Enter);

    assert!(session_starts(&second).is_empty());
    assert_eq!(
        harness.app.open_review_session_id(&finding),
        Some(session_id)
    );
}

#[test]
fn open_command_path_emits_session_effect() {
    let mut harness = harness(3);
    harness.arm();
    let finding = harness.app.findings()[1].clone();

    let effects = harness
        .app
        .finalize_open_finding_effect(OpenFindingFinalize {
            reference: finding.fingerprint.clone(),
            outcome: OpenFindingOutcome::Found(finding.clone()),
        });

    let apply = one_session_start(&effects);
    assert_eq!(apply.finding.fingerprint, finding.fingerprint);
    assert_eq!(apply.baseline_index, 1);
}

/// Without an operator-supplied artifact nothing is minted and nothing is
/// linked: the default shell behaves exactly as it did before this feature.
#[test]
fn no_model_configured_emits_no_session_and_null_session_on_decision() {
    let mut harness = harness(3);

    let effects = harness.press(KeyCode::Enter);
    assert!(session_starts(&effects).is_empty());

    let decision = harness
        .app
        .reduce_command_effects(&ShellCommand::ReviewDecision(
            ReviewDecisionCommand::Record {
                verdict: "confirmed".to_string(),
                reason: "reviewed without shadow recording".to_string(),
            },
        ))
        .expect("review decision is effect-routed");
    let apply = decision
        .into_iter()
        .find_map(|effect| match effect {
            ShellEffect::RecordReviewDecision(apply) => Some(apply),
            _ => None,
        })
        .expect("review decision effect");
    assert_eq!(apply.review_session_id, None);
}

/// A verdict closes the sitting it concluded. The next open of the same
/// finding is a new observation, not a continuation of the old one.
#[test]
fn decision_consumes_session_and_next_open_mints_new_id() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
        .unwrap();
    let mut finding = queue_finding(0, Severity::High);
    let finding_id = store.insert_finding("run-1", &finding).unwrap();
    finding.id = Some(finding_id);

    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_target(Some(workspace.root().to_path_buf()));
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ReviewQueue);
    app.set_findings(vec![finding.clone()]);
    app.set_findings_read_watermark(Some(12_000));
    arm_from_config(&mut app, ReviewYieldMode::Shadow, shadow_model_path());

    let first = app.open_finding_at_cursor();
    let first_session = one_session_start(&first).review_session_id.clone();

    let decision = app
        .reduce_command_effects(&ShellCommand::ReviewDecision(
            ReviewDecisionCommand::Record {
                verdict: "confirmed".to_string(),
                reason: "exploitable in this deployment".to_string(),
            },
        ))
        .expect("review decision is effect-routed");
    let apply = decision
        .into_iter()
        .find_map(|effect| match effect {
            ShellEffect::RecordReviewDecision(apply) => Some(apply),
            _ => None,
        })
        .expect("review decision effect");
    assert_eq!(
        apply.review_session_id.as_deref(),
        Some(first_session.as_str())
    );

    app.record_review_decision_effect(apply);
    assert_eq!(app.open_review_session_id(&finding), None);
    assert_eq!(store.list_review_decisions(finding_id).unwrap().len(), 1);

    let second = app.open_finding_at_cursor();
    let second_session = one_session_start(&second).review_session_id.clone();
    assert_ne!(second_session, first_session);
}

/// The scripted plain shell is the only shell a pipeline has. `open` then
/// `decision` must record the verdict there exactly as it does interactively,
/// joined to the session the open started — the open's own session-start event
/// is an observation and must not read as "the finding changed" underneath the
/// verdict it precedes.
#[test]
fn scripted_plain_open_then_decision_records_the_verdict_and_its_session() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
        .unwrap();
    let finding_id = store
        .insert_finding("run-1", &queue_finding(0, Severity::High))
        .unwrap();

    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_target(Some(workspace.root().to_path_buf()));
    app.refresh_findings(false);
    arm_from_config(&mut app, ReviewYieldMode::Shadow, shadow_model_path());

    let output = render_plain_scripted_session(
        &mut app,
        &[
            "open F-0001",
            "decision false-positive test fixture credential",
        ],
        100,
    );

    assert!(output.contains("decision saved"), "{output}");
    let decisions = store.list_review_decisions(finding_id).unwrap();
    assert_eq!(decisions.len(), 1, "{output}");
    let session = store
        .joined_review_session_id(decisions[0].id)
        .unwrap()
        .expect("the verdict must join to the session its open started");
    assert!(!session.is_empty());
}

/// Sessions and scores are facts about one repository. Carrying them across a
/// target switch would attribute one engagement's review to another.
#[test]
fn target_switch_clears_active_review_sessions() {
    let mut harness = harness(3);
    harness.arm();
    let finding = harness.app.findings()[0].clone();
    let effects = harness.press(KeyCode::Enter);
    assert_eq!(session_starts(&effects).len(), 1);

    harness.app.reset_review_sessions_for_target();

    assert_eq!(harness.app.open_review_session_id(&finding), None);
}

/// A rejected artifact turns review yield off. There is no degraded mode, no
/// second path is tried, and `visible` shows nothing rather than an empty
/// section.
#[test]
fn a_rejected_model_leaves_review_yield_off() {
    let mut harness = harness(3);
    let missing = harness.workspace.root().join("not-a-model.json");

    arm_from_config(&mut harness.app, ReviewYieldMode::Visible, missing);

    assert!(!harness.app.shows_review_yield_signal());

    assert!(harness.app.runtime_state.review_yield().model().is_none());
    let effects = harness.press(KeyCode::Enter);
    assert!(session_starts(&effects).is_empty());
}

// ---------------------------------------------------- byte-for-byte ordering

fn mixed_severity_queue() -> Vec<Finding> {
    [
        Severity::Low,
        Severity::Critical,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
        Severity::Low,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, severity)| queue_finding(index, severity))
    .collect()
}

/// The whole promise of shadow recording. Not "roughly the same order" — the
/// same aliases in the same positions, before and after the model is armed and
/// after scoring has actually run.
#[test]
fn shadow_model_preserves_review_queue_order_byte_for_byte() {
    let mut harness = harness(0);
    harness.app.set_findings(mixed_severity_queue());
    let baseline = visible_sorted_finding_alias_indices(&harness.app);
    assert!(baseline.len() > 1, "the queue must be worth ordering");

    harness.arm();
    let effects = harness.press(KeyCode::Enter);
    assert_eq!(session_starts(&effects).len(), 1, "scoring must have run");

    assert_eq!(visible_sorted_finding_alias_indices(&harness.app), baseline);
}

/// The backlog preset takes the severity-major bypass instead of the
/// confidence-first reorder. It is a second ordering path, so it needs its own
/// proof.
#[test]
fn shadow_model_preserves_backlog_order_byte_for_byte() {
    let mut harness = harness(0);
    harness.app.set_findings(mixed_severity_queue());
    {
        let review = harness.app.router.workbench_mut().review_mut();
        review.backlog = true;
        review.backlog_severity = Some("high");
    }
    let baseline = visible_sorted_finding_alias_indices(&harness.app);

    harness.arm();
    let effects = harness.press(KeyCode::Enter);
    assert_eq!(session_starts(&effects).len(), 1, "scoring must have run");

    assert_eq!(visible_sorted_finding_alias_indices(&harness.app), baseline);
    assert!(
        crate::ui_view_models::review_backlog_active(&harness.app),
        "the backlog bypass must still be the active path"
    );
}

// ----------------------------------------------------------- payload hygiene

/// The durable payload is built from queue identity and measurement only. A
/// path, a snippet, a message, or a rationale reaching it would turn a
/// measurement into a copy of the finding.
#[test]
fn review_session_payload_contains_no_raw_feature_values() {
    let mut harness = harness(0);
    harness.arm();
    let mut finding = queue_finding(0, Severity::High);
    finding.file_path = "src/api/checkout/handler.rs".to_string();
    finding.message = "tainted id reaches format!(\"select * from users\")".to_string();
    finding.title = "sql injection in checkout".to_string();
    finding.rule_id = "rules/injection/sql-string-concat".to_string();
    harness.app.set_findings(vec![finding.clone()]);

    let effects = harness.app.open_finding_at_cursor();
    let apply = one_session_start(&effects);
    let model = harness.app.runtime_state.review_yield().model().unwrap();
    let write = review_session_write(apply, &model, &HashMap::new());
    let payload = serde_json::to_string(&serde_json::json!({
        "reviewSessionId": write.review_session_id,
        "stableFp": write.stable_fp,
        "identityId": write.identity_id,
        "findingId": write.finding_id,
        "featureSchemaId": write.feature_schema_id,
        "featureSnapshotHash": write.feature_snapshot_hash,
        "featureCutoffSeq": write.feature_cutoff_seq,
        "modelId": write.model_id,
        "eligibility": write.eligibility,
        "baselineRank": write.baseline_rank,
        "shadowRank": write.shadow_rank,
        "queueSize": write.queue_size,
        "proofBand": write.proof_band,
        "severity": write.severity,
    }))
    .unwrap();

    for content in [
        "src/api/checkout/handler.rs",
        "select * from users",
        "sql injection in checkout",
        "rules/injection/sql-string-concat",
    ] {
        assert!(
            !payload.contains(content),
            "session payload leaked review content: {content}"
        );
    }
    assert_eq!(write.baseline_rank, 1);
    assert_eq!(write.queue_size, 1);
    // No score for this row, so no advisory rank is asserted for it.
    assert_eq!(write.eligibility, "noScoreRecorded");
    assert_eq!(write.shadow_rank, None);
    assert_eq!(write.feature_snapshot_hash, None);
}

// ------------------------------------------- visible mode changes nothing but

/// The whole safety argument for showing the signal: the operator's queue is
/// identical whether the signal is off or on screen. Both ordering paths, both
/// projections, byte for byte.
#[test]
fn visible_mode_keeps_projected_order_byte_for_byte() {
    for backlog in [false, true] {
        let mut harness = harness(0);
        harness.app.set_findings(mixed_severity_queue());
        if backlog {
            let review = harness.app.router.workbench_mut().review_mut();
            review.backlog = true;
            review.backlog_severity = Some("high");
        }
        let baseline_aliases = visible_sorted_finding_alias_indices(&harness.app);
        let baseline_queue = queue_row_identities(&harness.app);
        // The backlog bypass narrows to one severity; the confidence-first
        // path must still have several rows to get wrong.
        assert!(!baseline_queue.is_empty(), "backlog={backlog}");
        assert!(backlog || baseline_aliases.len() > 1, "nothing to order");

        harness.arm_in(ReviewYieldMode::Visible);
        let effects = harness.press(KeyCode::Enter);
        assert_eq!(session_starts(&effects).len(), 1, "scoring must have run");
        for effect in &effects {
            if let ShellEffect::RecordReviewSessionStart(apply) = effect {
                harness
                    .app
                    .record_review_session_effect(ReviewSessionApply {
                        target: apply.target.clone(),
                        finding: apply.finding.clone(),
                        review_session_id: apply.review_session_id.clone(),
                        feature_cutoff_seq: apply.feature_cutoff_seq,
                        queue: apply.queue.clone(),
                        baseline_index: apply.baseline_index,
                        objective: apply.objective,
                    });
            }
        }
        assert!(
            harness.app.shows_review_yield_signal(),
            "visible mode must be armed"
        );

        assert_eq!(
            visible_sorted_finding_alias_indices(&harness.app),
            baseline_aliases,
            "backlog={backlog}"
        );
        assert_eq!(
            queue_row_identities(&harness.app),
            baseline_queue,
            "backlog={backlog}"
        );
        assert_eq!(
            crate::ui_view_models::review_backlog_active(&harness.app),
            backlog
        );
    }
}

/// The rendered review queue, as the rows an operator would read off it, in
/// every queue mode the page offers.
fn queue_row_identities(app: &ShellApp) -> Vec<(String, String)> {
    [
        ReviewQueueMode::Open,
        ReviewQueueMode::Complete,
        ReviewQueueMode::All,
    ]
    .into_iter()
    .flat_map(|mode| {
        crate::ui_view_models::review_queue_model(app, mode)
            .rows
            .iter()
            .map(|row| (row.alias.clone(), row.title.clone()))
            .collect::<Vec<_>>()
    })
    .collect()
}

/// Shadow mode is silent by construction, not by the renderer choosing not to
/// draw: no view model is offered one in the first place.
#[test]
fn off_and_shadow_modes_attach_no_review_yield_section() {
    for mode in [None, Some(ReviewYieldMode::Shadow)] {
        let mut harness = harness(3);
        if let Some(mode) = mode {
            harness.arm_in(mode);
        }
        let finding = harness.app.findings()[0].clone();

        assert!(!harness.app.shows_review_yield_signal(), "{mode:?}");
        assert!(
            review_yield_detail_for(&harness.app, &finding).is_none(),
            "{mode:?}"
        );
    }
}

/// Visible mode never draws a blank. Before the queue is scored the section
/// says so and says what to do about it, rather than showing an empty number.
#[test]
fn visible_mode_before_scoring_explains_that_nothing_is_scored_yet() {
    let mut harness = harness(3);
    harness.arm_in(ReviewYieldMode::Visible);
    let finding = harness.app.findings()[0].clone();

    let detail = review_yield_detail_for(&harness.app, &finding)
        .expect("visible mode always attaches a section");

    let ReviewYieldDetailModel::Unavailable { message } = detail else {
        panic!("nothing has been scored yet, so there is no signal to show");
    };
    assert!(message.contains("not scored yet"), "{message}");
}

/// A re-open records nothing — it is the same session — but visible mode still
/// needs a score for the detail it is about to draw. Shadow mode, which shows
/// nothing, asks for no such work.
#[test]
fn a_reopen_rescores_only_when_the_signal_is_displayed() {
    for (mode, expected) in [(ReviewYieldMode::Shadow, 0), (ReviewYieldMode::Visible, 1)] {
        let mut harness = harness(3);
        harness.arm_in(mode);

        let first = harness.app.open_finding_at_cursor();
        assert_eq!(session_starts(&first).len(), 1, "{mode:?}");

        let second = harness.app.open_finding_at_cursor();
        assert!(session_starts(&second).is_empty(), "{mode:?}");
        let rescores = second
            .iter()
            .filter(|effect| matches!(effect, ShellEffect::ScoreReviewYieldQueue(_)))
            .count();
        assert_eq!(rescores, expected, "{mode:?}");
    }
}

/// End to end through the real effect: opening a finding scores the queue,
/// the score reaches the view model, and the renderer draws the section in
/// both the styled and the plain projection.
///
/// These findings carry no durable identity, so the honest answer is that no
/// review history joins to them — exactly the state that must render as a
/// sentence rather than a blank.
#[test]
fn visible_mode_renders_the_scored_state_in_styled_and_plain_output() {
    let mut harness = harness(3);
    harness.arm_in(ReviewYieldMode::Visible);
    let finding = harness.app.findings()[0].clone();

    let effects = harness.app.open_finding_at_cursor();
    let apply = one_session_start(&effects);
    let apply = ReviewSessionApply {
        target: apply.target.clone(),
        finding: apply.finding.clone(),
        review_session_id: apply.review_session_id.clone(),
        feature_cutoff_seq: apply.feature_cutoff_seq,
        queue: apply.queue.clone(),
        baseline_index: apply.baseline_index,
        objective: apply.objective,
    };
    harness.app.record_review_session_effect(apply);

    let detail = review_yield_detail_for(&harness.app, &finding)
        .expect("visible mode always attaches a section");
    let ReviewYieldDetailModel::Unavailable { message } = detail else {
        panic!("these findings have no durable identity, so no leaf is reachable");
    };
    assert!(message.contains("no durable identity"), "{message}");

    let plain = crate::renderer::render_plain_app(&harness.app, 120);
    assert!(plain.contains("REVIEW YIELD"), "{plain}");
    assert!(plain.contains(&message), "{plain}");
    assert!(
        plain.contains(crate::ui_view_models::REVIEW_YIELD_ADVISORY_LINE_1),
        "{plain}"
    );
    assert!(
        plain.contains(crate::ui_view_models::REVIEW_YIELD_ADVISORY_LINE_2),
        "{plain}"
    );
}

/// Plain output is the scripted shell's only view. A section that rendered
/// only under Ratatui would silently drop the qualification that keeps the
/// numbers honest.
#[test]
fn plain_output_omits_the_section_entirely_when_the_signal_is_off() {
    let mut harness = harness(3);
    let _ = harness.app.open_finding_at_cursor();

    let plain = crate::renderer::render_plain_app(&harness.app, 120);

    assert!(!plain.contains("REVIEW YIELD"), "{plain}");
    assert!(
        !plain.contains(crate::ui_view_models::REVIEW_YIELD_ADVISORY_LINE_1),
        "{plain}"
    );
}
