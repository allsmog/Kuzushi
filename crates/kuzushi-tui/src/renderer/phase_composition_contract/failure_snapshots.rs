//! Snapshot fixtures for the failure-path decision cards.
//!
//! The happy-path phase snapshots never show a RESULT READY card, so the
//! copy operators see at their most stressed moments — a failed, canceled,
//! or partial phase attempt, a blocked selection, a degraded ledger — had
//! zero fixture coverage. Each scenario here drives the real guided-scan
//! result flow over a real persisted attempt and snapshots the full frame,
//! which also feeds these screens through the rendered-surface lints and
//! the failure-state coverage matrix.
//!
//! Regenerate with the same env var as the phase snapshots:
//! `KUZUSHI_PHASE_SNAPSHOT_OUT=<abs .../snapshots/phase_cockpit> cargo test
//! -p kuzushi-tui --lib failure_snapshots`.

use super::contract::TerminalProfile;
use super::*;
use kuzushi_core::workflow_attempts::{
    append_phase_attempt_completed, phase_attempt_ledger_path, PhaseAttemptCompleted,
    PhaseAttemptOutcome, PhaseTargetSnapshot,
};
use kuzushi_core::{V2Config, WorkflowPhase, WorkspaceTarget};
use std::fs;
use std::path::{Path, PathBuf};

const FAILURE_CARD_CONTRACT: &str =
    "failure-path decision cards render honest outcome copy and recovery actions";

const FAILURE_SNAPSHOT_SIZE: (u16, u16) = (120, 36);

/// The production blocked-selection copy from
/// `runtime_event_drains.rs::live_health_adjusted_completion`.
const LIVE_SETTLEMENT_BLOCKED: &str =
    "live run settlement is not healthy and durable; inspect the run before continuing";

struct FailureScenario {
    slug: &'static str,
    phase: WorkflowPhase,
    outcome: PhaseAttemptOutcome,
    blocked_reason: Option<&'static str>,
    corrupt_ledger: bool,
    /// The failure copy this scenario exists to demonstrate; asserted
    /// against the rendered frame so the snapshot provably carries it.
    signature: &'static str,
}

const SCENARIOS: &[FailureScenario] = &[
    FailureScenario {
        slug: "result_failed",
        phase: WorkflowPhase::Map,
        outcome: PhaseAttemptOutcome::Failed,
        blocked_reason: None,
        corrupt_ledger: false,
        signature: "failed. Open the run or try again",
    },
    FailureScenario {
        slug: "result_canceled",
        phase: WorkflowPhase::Scan,
        outcome: PhaseAttemptOutcome::Canceled,
        blocked_reason: None,
        corrupt_ledger: false,
        signature: "was canceled. Open the run or try again",
    },
    FailureScenario {
        slug: "result_partial",
        phase: WorkflowPhase::Scan,
        outcome: PhaseAttemptOutcome::Partial,
        blocked_reason: None,
        corrupt_ledger: false,
        signature: "returned partial evidence",
    },
    FailureScenario {
        slug: "blocked_selection",
        phase: WorkflowPhase::Scan,
        outcome: PhaseAttemptOutcome::Partial,
        blocked_reason: Some(LIVE_SETTLEMENT_BLOCKED),
        corrupt_ledger: false,
        signature: "live run settlement is not healthy",
    },
    FailureScenario {
        slug: "degraded_ledger",
        phase: WorkflowPhase::Map,
        outcome: PhaseAttemptOutcome::Completed,
        blocked_reason: None,
        corrupt_ledger: true,
        signature: "ledger is degraded",
    },
];

struct FailureFixture {
    _target: tempfile::TempDir,
    target_root: PathBuf,
    canonical_target_root: PathBuf,
    target_name: String,
    app: ShellApp,
}

impl FailureFixture {
    fn new(scenario: &FailureScenario, width: u16, height: u16) -> Self {
        let target = tempfile::tempdir().expect("failure card target");
        let attempt_id = persist_scenario_attempt(scenario, target.path());
        let workspace = WorkspaceTarget::new(target.path()).expect("failure card workspace");
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.set_viewport(TerminalViewport::new(width, height));
        app.set_input_mode(InputMode::Navigate);
        app.refresh_phase_attempt_projection();
        assert!(
            app.await_guided_phase_result_for_test(scenario.phase, attempt_id),
            "{}: persisted attempt did not bind to the result card",
            scenario.slug
        );
        if scenario.corrupt_ledger {
            assert!(
                app.engagement.phase_attempt_projection_is_degraded(),
                "degraded_ledger scenario failed to degrade the projection"
            );
        }
        let target_root = target.path().to_path_buf();
        let canonical_target_root = target_root
            .canonicalize()
            .unwrap_or_else(|_| target_root.clone());
        let target_name = target_root
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("failure-target")
            .to_string();
        Self {
            _target: target,
            target_root,
            canonical_target_root,
            target_name,
            app,
        }
    }

    fn normalize(&self, rendered: String) -> String {
        rendered
            .replace(
                &self.canonical_target_root.display().to_string(),
                "/tmp/failure-target",
            )
            .replace(
                &self.target_root.display().to_string(),
                "/tmp/failure-target",
            )
            .replace(&self.target_name, "failure-target")
    }
}

fn persist_scenario_attempt(scenario: &FailureScenario, target: &Path) -> String {
    let attempt_id = format!("attempt-{}", scenario.slug);
    let mut completed = PhaseAttemptCompleted::new(
        scenario.phase,
        vec![format!("run-{}", scenario.slug)],
        PhaseTargetSnapshot::capture(target),
        scenario.outcome,
    )
    .with_attempt_id(attempt_id.clone());
    if let Some(reason) = scenario.blocked_reason {
        completed = completed.with_selection_blocked(reason);
    }
    append_phase_attempt_completed(target, completed).expect("persist failure attempt");
    if scenario.corrupt_ledger {
        corrupt_ledger_tail(target);
    }
    attempt_id
}

/// Appends one malformed event line so recovery keeps the valid prefix
/// (the attempt above) but marks the projection degraded.
fn corrupt_ledger_tail(target: &Path) {
    let path = phase_attempt_ledger_path(target);
    let mut content = fs::read_to_string(&path).expect("read failure ledger");
    content.push_str("{\"malformed\":\n");
    fs::write(&path, content).expect("corrupt failure ledger");
}

fn render_failure_card(scenario: &FailureScenario, width: u16, height: u16) -> String {
    let fixture = FailureFixture::new(scenario, width, height);
    let _theme = theme::scoped_theme_for_test(TerminalProfile::TrueColor.config());
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("failure card terminal");
    terminal
        .draw(|frame| render_app(frame, &fixture.app))
        .expect("failure card render");
    fixture.normalize(buffer_text(terminal.backend().buffer()))
}

fn assert_failure_snapshot(scenario: &FailureScenario, width: u16, height: u16, actual: &str) {
    let filename = format!("failure_{}_{}x{}.snap", scenario.slug, width, height);
    if let Some(root) = std::env::var_os("KUZUSHI_PHASE_SNAPSHOT_OUT") {
        let path = PathBuf::from(root).join(filename);
        fs::create_dir_all(path.parent().expect("failure snapshot parent"))
            .expect("failure snapshot directory");
        let document = format!(
            "---\nsource: Kuzushi Cockpit Spine\ncontract: {FAILURE_CARD_CONTRACT}\nscenario: {}\nsize: {width}x{height}\n---\n{}\n",
            scenario.slug,
            actual.trim_end()
        );
        fs::write(path, document).expect("failure snapshot output");
        return;
    }
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/renderer/snapshots/phase_cockpit")
        .join(filename);
    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let body = expected
        .split_once("---\n")
        .and_then(|(_, rest)| rest.split_once("---\n"))
        .map(|(_, body)| body)
        .unwrap_or(&expected);
    assert_eq!(body.trim_end(), actual.trim_end(), "{}", path.display());
}

#[test]
fn failure_card_reference_has_canonical_buffer_snapshots() {
    let (width, height) = FAILURE_SNAPSHOT_SIZE;
    for scenario in SCENARIOS {
        let text = render_failure_card(scenario, width, height);
        assert_failure_snapshot(scenario, width, height, &text);
    }
}

#[test]
fn failure_snapshots_carry_their_failure_copy() {
    let (width, height) = FAILURE_SNAPSHOT_SIZE;
    for scenario in SCENARIOS {
        let text = render_failure_card(scenario, width, height);
        assert!(
            text.contains(scenario.signature),
            "{}: rendered frame lost its failure copy {:?}\n{text}",
            scenario.slug,
            scenario.signature
        );
        assert!(
            text.contains("RESULT READY"),
            "{}: rendered frame lost the RESULT READY card title\n{text}",
            scenario.slug
        );
    }
}

/// One reconciled NEXT per stressed screen. The result card once printed
/// three competing continuations at the same time — the phase spine hint,
/// the receipt's "Receipt NEXT", and the terminal cell's "NEXT · none" —
/// and the operator had to guess which one was true.
#[test]
fn failure_cards_render_exactly_one_reconciled_next() {
    let (width, height) = FAILURE_SNAPSHOT_SIZE;
    for scenario in SCENARIOS {
        let text = render_failure_card(scenario, width, height);
        let next_count = text.matches("NEXT").count();
        assert_eq!(
            next_count, 1,
            "{}: a failure card must carry exactly one NEXT, found {next_count}\n{text}",
            scenario.slug
        );
        assert!(
            !text.contains("NEXT \u{b7} none"),
            "{}: an absent continuation is omitted, never printed as none\n{text}",
            scenario.slug
        );
    }
}

#[test]
fn failure_card_rendering_is_deterministic() {
    let (width, height) = FAILURE_SNAPSHOT_SIZE;
    let scenario = &SCENARIOS[0];
    assert_eq!(
        render_failure_card(scenario, width, height),
        render_failure_card(scenario, width, height),
        "two renders of the same scenario diverged — nondeterministic \
         content (timestamps, generated ids) leaked into the frame"
    );
}
