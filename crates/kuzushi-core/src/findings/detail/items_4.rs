use super::prelude::*;
use super::*;

pub fn proof_ladder_state(
    finding: &Finding,
    latest_patch: Option<&PatchResult>,
) -> ProofLadderState {
    if matches!(
        latest_patch.map(|patch| patch.status),
        Some(PatchStatus::Sound | PatchStatus::Verified)
    ) {
        return proof_ladder(
            "patched",
            "patched - remediation evidence recorded",
            "latest patch result is sound or verified",
            "review the PR comment and keep post-patch validation attached",
        );
    }
    if matches!(
        finding.verification.as_ref().map(|v| v.proof_verdict),
        Some(PersistedProofVerdict::Exploited)
    ) {
        return proof_ladder(
            "validated",
            "validated - empirical runtime evidence recorded",
            "runtime validation reproduced exploitability",
            "patch the finding and re-run validation",
        );
    }
    if matches!(
        finding.static_proof_state,
        Some(StaticProofState::SourceSinkLinked | StaticProofState::SanitizerChecked)
    ) {
        return proof_ladder(
            "path_linked",
            "path-linked - static source/sink evidence recorded",
            "static evidence links a source to a sink or sanitizer assessment",
            "run verify:finding or attach runtime evidence",
        );
    }
    if matches!(
        finding.static_proof_state,
        Some(StaticProofState::CodeCited | StaticProofState::StaticallyConfirmed)
    ) {
        return proof_ladder(
            "source_grounded",
            "source-grounded - code evidence recorded",
            "the finding cites source evidence but not a validated path",
            "collect source/sink path evidence or validate runtime behavior",
        );
    }
    if matches!(
        finding.static_proof_state,
        Some(StaticProofState::StaticallyRejected)
    ) || matches!(
        finding.triage.as_ref().map(|triage| triage.verdict),
        Some(TriageVerdict::FalsePositive | TriageVerdict::ByDesign)
    ) {
        return proof_ladder(
            "rejected",
            "rejected - evidence does not support exploitability",
            "triage or static proof rejected the issue",
            "suppress with expiry if the operator accepts the evidence",
        );
    }
    proof_ladder(
        "suspected",
        "suspected - needs source grounding or validation",
        "scanner signal has not been promoted with inspectable proof",
        "open the finding, collect code evidence, then validate if warranted",
    )
}

pub(in crate::findings) fn proof_ladder(
    stage: &str,
    label: &str,
    reason: &str,
    next_step: &str,
) -> ProofLadderState {
    ProofLadderState {
        stage: stage.to_string(),
        label: label.to_string(),
        reason: reason.to_string(),
        next_step: next_step.to_string(),
    }
}

pub(in crate::findings) fn indent_lines(value: &str) -> Vec<String> {
    value
        .lines()
        .map(|line| format!("  {}", line.trim_end()))
        .collect()
}
