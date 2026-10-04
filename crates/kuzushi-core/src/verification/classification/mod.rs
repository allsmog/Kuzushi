use super::*;
use kuzushi_sandbox::{ExitOutcome, SandboxExecResult};
use std::io::Read;

pub(crate) const SINK_MARKER_ENV: &str = "KUZUSHI_SINK_MARKER";
pub(crate) const SINK_MARKER_FILE: &str = ".kuzushi-sink-reached-v1";
pub(crate) const SINK_MARKER_CONTENT: &str = "kuzushi-sink-reached-v1";
const MAX_RUNTIME_EVIDENCE_CHARS: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarnessFidelity {
    Faithful,
    PayloadOnly,
    Placeholder,
}

impl HarnessFidelity {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Faithful => "faithful",
            Self::PayloadOnly => "payload-only",
            Self::Placeholder => "placeholder",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SinkEvidence {
    Reached,
    NotReached,
    Invalid(String),
}

struct RunClassification {
    proof_level: u8,
    proof_verdict: ProofVerdict,
    note: String,
}

/// Classify a sandbox run only when a faithful harness proves that execution
/// reached the generated sink call.
pub fn classify_run_result(
    run: &SandboxExecResult,
    backend: SandboxBackend,
    project_path: &Path,
    fidelity: HarnessFidelity,
) -> VerificationOutcome {
    if fidelity != HarnessFidelity::Faithful {
        return not_attempted_for_harness(backend, fidelity);
    }

    let sink_evidence = read_sink_evidence(project_path);
    let classification = classify_observation(run, sink_evidence);

    VerificationOutcome {
        proof_level: classification.proof_level,
        proof_verdict: classification.proof_verdict,
        backend,
        language: None,
        harness_path: Some(project_path.to_path_buf()),
        crash_evidence: bounded_runtime_evidence(&run.stderr),
        duration_ms: run.duration_ms,
        cost_usd: 0.0,
        notes: vec![classification.note],
        provenance: None,
    }
}

fn classify_observation(run: &SandboxExecResult, evidence: SinkEvidence) -> RunClassification {
    if matches!(
        run.outcome,
        ExitOutcome::TimedOut | ExitOutcome::OutputLimitExceeded
    ) {
        return infrastructure_classification(
            "verify: harness exceeded its time/output budget; runtime result is inconclusive"
                .to_string(),
        );
    }
    match evidence {
        SinkEvidence::Reached => classify_reached_sink(run),
        SinkEvidence::NotReached => infrastructure_classification(
            "verify: harness terminated without durable reached-sink evidence; runtime result is inconclusive"
                .to_string(),
        ),
        SinkEvidence::Invalid(reason) => infrastructure_classification(format!(
            "verify: reached-sink marker was invalid ({reason}); runtime result is inconclusive"
        )),
    }
}

fn classify_reached_sink(run: &SandboxExecResult) -> RunClassification {
    if observed_crash(run) {
        return RunClassification {
            proof_level: 4,
            proof_verdict: ProofVerdict::Exploited,
            note: "verify: sink marker matched before the observed crash".to_string(),
        };
    }
    if run.outcome == ExitOutcome::Exited && run.exit_code == Some(0) {
        return RunClassification {
            proof_level: 2,
            proof_verdict: ProofVerdict::NotReproduced,
            note: "verify: sink marker matched and the harness exited cleanly".to_string(),
        };
    }
    infrastructure_classification(
        "verify: sink was reached but the harness had an unexplained nonzero or non-crash termination"
            .to_string(),
    )
}

fn observed_crash(run: &SandboxExecResult) -> bool {
    // Target-controlled stderr is supporting text, never a trusted crash oracle.
    run.outcome == ExitOutcome::Signaled && run.signal.is_some_and(is_crash_signal)
}

fn infrastructure_classification(note: String) -> RunClassification {
    RunClassification {
        proof_level: 1,
        proof_verdict: ProofVerdict::InfrastructureError,
        note,
    }
}

pub(crate) fn not_attempted_for_harness(
    backend: SandboxBackend,
    fidelity: HarnessFidelity,
) -> VerificationOutcome {
    VerificationOutcome::not_attempted(
        backend,
        format!(
            "{} harness does not invoke the finding sink; compile and execution were skipped",
            fidelity.label()
        ),
    )
}

pub(crate) fn prepare_sink_marker(project_path: &Path) -> Result<()> {
    let marker_path = sink_marker_path(project_path);
    match std::fs::symlink_metadata(&marker_path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            std::fs::remove_file(&marker_path).with_context(|| {
                format!(
                    "could not remove stale sink marker {}",
                    marker_path.display()
                )
            })?;
        }
        Ok(_) => anyhow::bail!(
            "refusing to replace non-regular stale sink marker {}",
            marker_path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "could not inspect stale sink marker {}",
                    marker_path.display()
                )
            });
        }
    }
    Ok(())
}

pub(crate) fn configure_sink_marker(command: &mut SandboxExecOptions, project_path: &Path) {
    command.env.insert(
        SINK_MARKER_ENV.to_string(),
        sink_marker_path(project_path).display().to_string(),
    );
}

pub(crate) fn sink_marker_path(project_path: &Path) -> PathBuf {
    project_path.join(SINK_MARKER_FILE)
}

fn read_sink_evidence(project_path: &Path) -> SinkEvidence {
    let marker_path = sink_marker_path(project_path);
    let marker = match std::fs::File::open(&marker_path) {
        Ok(marker) => marker,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return SinkEvidence::NotReached;
        }
        Err(error) => return SinkEvidence::Invalid(error.to_string()),
    };
    match marker.metadata() {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => return SinkEvidence::Invalid("marker is not a regular file".to_string()),
        Err(error) => return SinkEvidence::Invalid(error.to_string()),
    }

    let mut bytes = Vec::with_capacity(SINK_MARKER_CONTENT.len() + 1);
    if let Err(error) = marker
        .take((SINK_MARKER_CONTENT.len() + 1) as u64)
        .read_to_end(&mut bytes)
    {
        return SinkEvidence::Invalid(error.to_string());
    }
    if bytes == SINK_MARKER_CONTENT.as_bytes() {
        SinkEvidence::Reached
    } else {
        SinkEvidence::Invalid("marker content did not match".to_string())
    }
}

pub(crate) fn bounded_runtime_evidence(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    let redacted = crate::session_transcript::redaction::redact_text(value);
    let mut chars = redacted.chars();
    let mut bounded = chars
        .by_ref()
        .take(MAX_RUNTIME_EVIDENCE_CHARS)
        .collect::<String>();
    if chars.next().is_some() {
        bounded.push_str("\n[kuzushi verify evidence truncated]");
    }
    Some(bounded)
}

pub(super) fn is_crash_signal(sig: i32) -> bool {
    matches!(sig, 4 | 6 | 7 | 11)
}
