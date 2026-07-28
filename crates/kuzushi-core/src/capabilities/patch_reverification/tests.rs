use super::*;
use crate::verification::{EmpiricalCaseExpectation, EmpiricalCaseOracle, EmpiricalInputCase};
use std::collections::VecDeque;
use std::sync::Mutex;

struct FakeRunner {
    outcomes: Mutex<VecDeque<EmpiricalCaseExecution>>,
}

impl FakeRunner {
    fn new(outcomes: impl IntoIterator<Item = PatchEmpiricalOutcome>) -> Self {
        Self {
            outcomes: Mutex::new(
                outcomes
                    .into_iter()
                    .map(|outcome| EmpiricalCaseExecution {
                        reached_sink: outcome != PatchEmpiricalOutcome::Ambiguous,
                        outcome,
                    })
                    .collect(),
            ),
        }
    }
}

impl EmpiricalCaseRunner for FakeRunner {
    fn run_case(&self, _request: EmpiricalCaseRequest<'_>) -> EmpiricalCaseExecution {
        self.outcomes.lock().unwrap().pop_front().unwrap()
    }
}

fn cases() -> Vec<EmpiricalInputCase> {
    vec![
        case("original", EmpiricalInputCaseKind::OriginalAttack),
        case("control", EmpiricalInputCaseKind::BenignControl),
        case("variant-1", EmpiricalInputCaseKind::Variant),
    ]
}

fn case(id: &str, kind: EmpiricalInputCaseKind) -> EmpiricalInputCase {
    EmpiricalInputCase {
        id: id.to_string(),
        kind,
        payload: vec![1, 2, 3],
        oracle: EmpiricalCaseOracle {
            vulnerable: if kind == EmpiricalInputCaseKind::BenignControl {
                EmpiricalCaseExpectation::CleanExit
            } else {
                EmpiricalCaseExpectation::Exploited
            },
            patched: EmpiricalCaseExpectation::CleanExit,
        },
    }
}

fn finding() -> Finding {
    Finding::new_tool(
        "tool",
        "rule",
        "src/lib.rs",
        1,
        Some(1),
        crate::findings::Severity::High,
        "finding",
    )
}

fn evaluate(
    outcomes: &[PatchEmpiricalOutcome],
    backend: PersistedSandboxBackend,
) -> LadderEvaluation {
    run_case_ladder(
        &FakeRunner::new(outcomes.iter().copied()),
        Path::new("/vulnerable"),
        Path::new("/patched"),
        &finding(),
        backend,
        &cases(),
        1_000,
        10_000,
    )
}

#[test]
fn all_empirical_steps_pass_before_detector_replay() {
    let run = evaluate(
        &[
            PatchEmpiricalOutcome::Exploited,
            PatchEmpiricalOutcome::CleanExit,
            PatchEmpiricalOutcome::CleanExit,
            PatchEmpiricalOutcome::CleanExit,
            PatchEmpiricalOutcome::Exploited,
            PatchEmpiricalOutcome::CleanExit,
        ],
        PersistedSandboxBackend::Bwrap,
    );
    assert_eq!(run.terminal_state, None);
    assert_eq!(run.steps.len(), 6);
    assert!(run.steps.iter().all(|step| step.passed));
    assert_eq!(
        empirical_detector_state(
            run.terminal_state,
            PatchDetectorReplayOutcome::NotRediscovered,
        ),
        PatchLifecycleState::Verified
    );
}

#[test]
fn detector_rediscovery_after_a_clean_ladder_is_still_vulnerable() {
    assert_eq!(
        empirical_detector_state(None, PatchDetectorReplayOutcome::Rediscovered),
        PatchLifecycleState::StillVulnerable
    );
}

#[test]
fn baseline_failure_is_inconclusive() {
    let run = evaluate(
        &[PatchEmpiricalOutcome::CleanExit],
        PersistedSandboxBackend::Bwrap,
    );
    assert_eq!(run.terminal_state, Some(PatchLifecycleState::Inconclusive));
}

#[test]
fn patched_control_regression_fails() {
    let run = evaluate(
        &[
            PatchEmpiricalOutcome::Exploited,
            PatchEmpiricalOutcome::CleanExit,
            PatchEmpiricalOutcome::Exploited,
        ],
        PersistedSandboxBackend::Bwrap,
    );
    assert_eq!(run.terminal_state, Some(PatchLifecycleState::Failed));
}

#[test]
fn ambiguous_control_is_inconclusive() {
    let run = evaluate(
        &[
            PatchEmpiricalOutcome::Exploited,
            PatchEmpiricalOutcome::CleanExit,
            PatchEmpiricalOutcome::Ambiguous,
        ],
        PersistedSandboxBackend::Bwrap,
    );
    assert_eq!(run.terminal_state, Some(PatchLifecycleState::Inconclusive));
}

#[test]
fn surviving_original_is_still_vulnerable() {
    let run = evaluate(
        &[
            PatchEmpiricalOutcome::Exploited,
            PatchEmpiricalOutcome::CleanExit,
            PatchEmpiricalOutcome::CleanExit,
            PatchEmpiricalOutcome::Exploited,
        ],
        PersistedSandboxBackend::Bwrap,
    );
    assert_eq!(
        run.terminal_state,
        Some(PatchLifecycleState::StillVulnerable)
    );
}

#[test]
fn variant_that_fails_baseline_is_inconclusive() {
    let run = evaluate(
        &[
            PatchEmpiricalOutcome::Exploited,
            PatchEmpiricalOutcome::CleanExit,
            PatchEmpiricalOutcome::CleanExit,
            PatchEmpiricalOutcome::CleanExit,
            PatchEmpiricalOutcome::CleanExit,
        ],
        PersistedSandboxBackend::Bwrap,
    );
    assert_eq!(run.terminal_state, Some(PatchLifecycleState::Inconclusive));
}

#[test]
fn surviving_variant_is_still_vulnerable() {
    let run = evaluate(
        &[
            PatchEmpiricalOutcome::Exploited,
            PatchEmpiricalOutcome::CleanExit,
            PatchEmpiricalOutcome::CleanExit,
            PatchEmpiricalOutcome::CleanExit,
            PatchEmpiricalOutcome::Exploited,
            PatchEmpiricalOutcome::Exploited,
        ],
        PersistedSandboxBackend::Bwrap,
    );
    assert_eq!(
        run.terminal_state,
        Some(PatchLifecycleState::StillVulnerable)
    );
}

#[test]
fn nonisolating_backend_never_runs_or_verifies() {
    for backend in [
        PersistedSandboxBackend::Plain,
        PersistedSandboxBackend::Podman,
        PersistedSandboxBackend::Model,
    ] {
        let run = evaluate(&[], backend);
        assert_eq!(
            run.terminal_state,
            Some(PatchLifecycleState::Inconclusive),
            "{backend:?}"
        );
        assert!(run.steps.is_empty(), "{backend:?}");
    }
}
