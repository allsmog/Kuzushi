use crate::findings::{Finding, PatchEmpiricalOutcome, PersistedSandboxBackend};
use crate::verification::{ProofVerdict, VerifyOptions};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EmpiricalCaseExecution {
    pub(crate) outcome: PatchEmpiricalOutcome,
    pub(crate) reached_sink: bool,
}

pub(crate) struct EmpiricalCaseRequest<'a> {
    pub(crate) checkout: &'a Path,
    pub(crate) finding: &'a Finding,
    pub(crate) payload: &'a [u8],
    pub(crate) backend: PersistedSandboxBackend,
    pub(crate) timeout_ms: u64,
}

pub(crate) trait EmpiricalCaseRunner {
    fn run_case(&self, request: EmpiricalCaseRequest<'_>) -> EmpiricalCaseExecution;
}

pub(crate) struct ProductionEmpiricalCaseRunner;

impl EmpiricalCaseRunner for ProductionEmpiricalCaseRunner {
    fn run_case(&self, request: EmpiricalCaseRequest<'_>) -> EmpiricalCaseExecution {
        let Some(backend) = isolating_backend(request.backend) else {
            return ambiguous_execution();
        };
        execute_empirical_case(request, backend)
    }
}

fn isolating_backend(backend: PersistedSandboxBackend) -> Option<kuzushi_sandbox::SandboxBackend> {
    match backend {
        PersistedSandboxBackend::Bwrap => Some(kuzushi_sandbox::SandboxBackend::Bwrap),
        PersistedSandboxBackend::Podman
        | PersistedSandboxBackend::Plain
        | PersistedSandboxBackend::Model => None,
    }
}

fn execute_empirical_case(
    request: EmpiricalCaseRequest<'_>,
    backend: kuzushi_sandbox::SandboxBackend,
) -> EmpiricalCaseExecution {
    let result = std::thread::scope(|scope| {
        scope
            .spawn(move || verify_empirical_case(request, backend))
            .join()
    });
    let Ok(Ok(outcome)) = result else {
        return ambiguous_execution();
    };
    execution_for_verdict(outcome.proof_verdict)
}

fn verify_empirical_case(
    request: EmpiricalCaseRequest<'_>,
    backend: kuzushi_sandbox::SandboxBackend,
) -> anyhow::Result<crate::verification::VerificationOutcome> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(crate::verification::verify_finding_with_payload(
        request.finding,
        VerifyOptions {
            backend: Some(backend),
            timeout_ms: request.timeout_ms,
            trust_plain_backend: false,
        },
        request.checkout,
        Some(request.payload),
    ))
}

fn execution_for_verdict(verdict: ProofVerdict) -> EmpiricalCaseExecution {
    match verdict {
        ProofVerdict::Exploited => EmpiricalCaseExecution {
            outcome: PatchEmpiricalOutcome::Exploited,
            reached_sink: true,
        },
        ProofVerdict::NotReproduced => EmpiricalCaseExecution {
            outcome: PatchEmpiricalOutcome::CleanExit,
            reached_sink: true,
        },
        _ => ambiguous_execution(),
    }
}

pub(super) fn ambiguous_execution() -> EmpiricalCaseExecution {
    EmpiricalCaseExecution {
        outcome: PatchEmpiricalOutcome::Ambiguous,
        reached_sink: false,
    }
}
