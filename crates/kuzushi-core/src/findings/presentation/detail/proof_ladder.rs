use super::proof_ladder_labels::proof_ladder_text;
use super::*;

pub fn proof_ladder_state(
    finding: &Finding,
    latest_patch: Option<&PatchResult>,
) -> ProofLadderState {
    let text = proof_ladder_text(proof_ladder_kind(finding, latest_patch));
    proof_ladder(text.stage, text.label, text.reason, text.next_step)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::findings) enum ProofLadderKind {
    Patched,
    Validated,
    PathLinked,
    SourceGrounded,
    Rejected,
    Suspected,
}

fn proof_ladder_kind(finding: &Finding, latest_patch: Option<&PatchResult>) -> ProofLadderKind {
    [
        patched_ladder_kind(latest_patch),
        validated_ladder_kind(finding),
        path_linked_ladder_kind(finding),
        source_grounded_ladder_kind(finding),
        rejected_ladder_kind(finding),
    ]
    .into_iter()
    .flatten()
    .next()
    .unwrap_or(ProofLadderKind::Suspected)
}

fn patched_ladder_kind(latest_patch: Option<&PatchResult>) -> Option<ProofLadderKind> {
    matches!(
        latest_patch.map(|patch| patch.status),
        Some(PatchStatus::Sound | PatchStatus::Verified)
    )
    .then_some(ProofLadderKind::Patched)
}

fn validated_ladder_kind(finding: &Finding) -> Option<ProofLadderKind> {
    matches!(
        finding.verification.as_ref().map(|v| v.proof_verdict),
        Some(PersistedProofVerdict::Exploited)
    )
    .then_some(ProofLadderKind::Validated)
}

fn path_linked_ladder_kind(finding: &Finding) -> Option<ProofLadderKind> {
    matches!(
        finding.static_proof_state,
        Some(StaticProofState::SourceSinkLinked | StaticProofState::SanitizerChecked)
    )
    .then_some(ProofLadderKind::PathLinked)
}

fn source_grounded_ladder_kind(finding: &Finding) -> Option<ProofLadderKind> {
    matches!(
        finding.static_proof_state,
        Some(StaticProofState::CodeCited | StaticProofState::StaticallyConfirmed)
    )
    .then_some(ProofLadderKind::SourceGrounded)
}

fn rejected_ladder_kind(finding: &Finding) -> Option<ProofLadderKind> {
    (matches!(
        finding.static_proof_state,
        Some(StaticProofState::StaticallyRejected)
    ) || matches!(
        finding.triage.as_ref().map(|triage| triage.verdict),
        Some(TriageVerdict::FalsePositive | TriageVerdict::ByDesign)
    ))
    .then_some(ProofLadderKind::Rejected)
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
