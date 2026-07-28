use super::execution::{ambiguous_execution, EmpiricalCaseRequest, EmpiricalCaseRunner};
use crate::findings::{
    Finding, PatchEmpiricalOutcome, PatchLifecycleState, PatchReverificationCaseKind,
    PatchReverificationStep, PatchReverificationTarget, PersistedSandboxBackend,
};
use crate::verification::{EmpiricalInputCase, EmpiricalInputCaseKind};
use std::path::Path;
use std::time::Instant;

pub(super) struct LadderEvaluation {
    pub(super) terminal_state: Option<PatchLifecycleState>,
    pub(super) steps: Vec<PatchReverificationStep>,
}

pub(super) fn run_case_ladder(
    runner: &dyn EmpiricalCaseRunner,
    vulnerable: &Path,
    patched: &Path,
    finding: &Finding,
    backend: PersistedSandboxBackend,
    cases: &[EmpiricalInputCase],
    per_case_timeout_ms: u64,
    aggregate_timeout_ms: u64,
) -> LadderEvaluation {
    if !is_isolating(backend) {
        return terminal(PatchLifecycleState::Inconclusive, Vec::new());
    }
    let cases = LadderCases::new(cases);
    let mut ladder = CaseLadder::new(
        runner,
        vulnerable,
        patched,
        finding,
        backend,
        per_case_timeout_ms,
        aggregate_timeout_ms,
    );
    if let Some(state) = ladder.run_vulnerable_calibration(&cases) {
        return ladder.finish(state);
    }
    if let Some(state) = ladder.run_patched_calibration(&cases) {
        return ladder.finish(state);
    }
    ladder.run_variants(cases.variants)
}

fn is_isolating(backend: PersistedSandboxBackend) -> bool {
    backend == PersistedSandboxBackend::Bwrap
}

struct LadderCases<'a> {
    original: &'a EmpiricalInputCase,
    control: &'a EmpiricalInputCase,
    variants: Vec<&'a EmpiricalInputCase>,
}

impl<'a> LadderCases<'a> {
    fn new(cases: &'a [EmpiricalInputCase]) -> Self {
        Self {
            original: find_case(
                cases,
                EmpiricalInputCaseKind::OriginalAttack,
                "checked reproducer has an original case",
            ),
            control: find_case(
                cases,
                EmpiricalInputCaseKind::BenignControl,
                "checked reproducer has a control case",
            ),
            variants: cases
                .iter()
                .filter(|case| case.kind == EmpiricalInputCaseKind::Variant)
                .collect(),
        }
    }
}

fn find_case<'a>(
    cases: &'a [EmpiricalInputCase],
    kind: EmpiricalInputCaseKind,
    missing_message: &str,
) -> &'a EmpiricalInputCase {
    cases
        .iter()
        .find(|case| case.kind == kind)
        .unwrap_or_else(|| panic!("{missing_message}"))
}

struct CaseLadder<'a> {
    executor: StepExecutor<'a>,
    steps: Vec<PatchReverificationStep>,
}

impl<'a> CaseLadder<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        runner: &'a dyn EmpiricalCaseRunner,
        vulnerable: &'a Path,
        patched: &'a Path,
        finding: &'a Finding,
        backend: PersistedSandboxBackend,
        per_case_timeout_ms: u64,
        aggregate_timeout_ms: u64,
    ) -> Self {
        Self {
            executor: StepExecutor {
                runner,
                vulnerable,
                patched,
                finding,
                backend,
                per_case_timeout_ms,
                aggregate_timeout_ms,
                started: Instant::now(),
            },
            steps: Vec::new(),
        }
    }

    fn run_vulnerable_calibration(
        &mut self,
        cases: &LadderCases<'_>,
    ) -> Option<PatchLifecycleState> {
        if self.run_vulnerable(cases.original, PatchEmpiricalOutcome::Exploited)
            != PatchEmpiricalOutcome::Exploited
        {
            return Some(PatchLifecycleState::Inconclusive);
        }
        if self.run_vulnerable(cases.control, PatchEmpiricalOutcome::CleanExit)
            != PatchEmpiricalOutcome::CleanExit
        {
            return Some(PatchLifecycleState::Inconclusive);
        }
        None
    }

    fn run_patched_calibration(&mut self, cases: &LadderCases<'_>) -> Option<PatchLifecycleState> {
        if let Some(state) = self.run_patched(cases.control, PatchLifecycleState::Failed) {
            return Some(state);
        }
        self.run_patched(cases.original, PatchLifecycleState::StillVulnerable)
    }

    fn run_variants(mut self, variants: Vec<&EmpiricalInputCase>) -> LadderEvaluation {
        for variant in variants {
            if self.run_vulnerable(variant, PatchEmpiricalOutcome::Exploited)
                != PatchEmpiricalOutcome::Exploited
            {
                return self.finish(PatchLifecycleState::Inconclusive);
            }
            if let Some(state) = self.run_patched(variant, PatchLifecycleState::StillVulnerable) {
                return self.finish(state);
            }
        }
        LadderEvaluation {
            terminal_state: None,
            steps: self.steps,
        }
    }

    fn run_vulnerable(
        &mut self,
        case: &EmpiricalInputCase,
        expected: PatchEmpiricalOutcome,
    ) -> PatchEmpiricalOutcome {
        self.record_step(case, PatchReverificationTarget::Vulnerable, expected)
    }

    fn run_patched(
        &mut self,
        case: &EmpiricalInputCase,
        exploited_state: PatchLifecycleState,
    ) -> Option<PatchLifecycleState> {
        match self.record_step(
            case,
            PatchReverificationTarget::Patched,
            PatchEmpiricalOutcome::CleanExit,
        ) {
            PatchEmpiricalOutcome::CleanExit => None,
            PatchEmpiricalOutcome::Exploited => Some(exploited_state),
            PatchEmpiricalOutcome::Ambiguous => Some(PatchLifecycleState::Inconclusive),
        }
    }

    fn record_step(
        &mut self,
        case: &EmpiricalInputCase,
        target: PatchReverificationTarget,
        expected: PatchEmpiricalOutcome,
    ) -> PatchEmpiricalOutcome {
        let step = self.executor.run(case, target, expected);
        let outcome = step.outcome;
        self.steps.push(step);
        outcome
    }

    fn finish(self, state: PatchLifecycleState) -> LadderEvaluation {
        terminal(state, self.steps)
    }
}

struct StepExecutor<'a> {
    runner: &'a dyn EmpiricalCaseRunner,
    vulnerable: &'a Path,
    patched: &'a Path,
    finding: &'a Finding,
    backend: PersistedSandboxBackend,
    per_case_timeout_ms: u64,
    aggregate_timeout_ms: u64,
    started: Instant,
}

impl StepExecutor<'_> {
    fn run(
        &self,
        case: &EmpiricalInputCase,
        target: PatchReverificationTarget,
        expected: PatchEmpiricalOutcome,
    ) -> PatchReverificationStep {
        let execution = self.execute(case, target);
        PatchReverificationStep {
            case_id: case.id.clone(),
            case_kind: case_kind(case.kind),
            target,
            input_digest: crate::identity::hash_parts(
                "kuzushi.patch.reverify.input.v1",
                &[&case.payload],
            )
            .to_string(),
            backend: self.backend,
            outcome: execution.outcome,
            reached_sink: execution.reached_sink,
            passed: execution.outcome == expected && execution.reached_sink,
        }
    }

    fn execute(
        &self,
        case: &EmpiricalInputCase,
        target: PatchReverificationTarget,
    ) -> super::EmpiricalCaseExecution {
        let remaining_ms = self.remaining_ms();
        if remaining_ms == 0 {
            return ambiguous_execution();
        }
        self.runner.run_case(EmpiricalCaseRequest {
            checkout: self.checkout(target),
            finding: self.finding,
            payload: &case.payload,
            backend: self.backend,
            timeout_ms: (self.per_case_timeout_ms.min(remaining_ms) / 2).max(1),
        })
    }

    fn remaining_ms(&self) -> u64 {
        let elapsed_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.aggregate_timeout_ms.saturating_sub(elapsed_ms)
    }

    fn checkout(&self, target: PatchReverificationTarget) -> &Path {
        match target {
            PatchReverificationTarget::Vulnerable => self.vulnerable,
            PatchReverificationTarget::Patched => self.patched,
        }
    }
}

fn terminal(state: PatchLifecycleState, steps: Vec<PatchReverificationStep>) -> LadderEvaluation {
    LadderEvaluation {
        terminal_state: Some(state),
        steps,
    }
}

fn case_kind(kind: EmpiricalInputCaseKind) -> PatchReverificationCaseKind {
    match kind {
        EmpiricalInputCaseKind::OriginalAttack => PatchReverificationCaseKind::OriginalAttack,
        EmpiricalInputCaseKind::BenignControl => PatchReverificationCaseKind::BenignControl,
        EmpiricalInputCaseKind::Variant => PatchReverificationCaseKind::Variant,
    }
}
