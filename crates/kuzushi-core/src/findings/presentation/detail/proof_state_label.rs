use super::*;

pub fn proof_state_label(state: Option<StaticProofState>) -> &'static str {
    state
        .and_then(proof_state_recorded_label)
        .unwrap_or("not recorded")
}

fn proof_state_recorded_label(state: StaticProofState) -> Option<&'static str> {
    PROOF_STATE_LABELS
        .iter()
        .find_map(|(candidate, label)| (*candidate == state).then_some(*label))
}

const PROOF_STATE_LABELS: &[(StaticProofState, &str)] = &[
    (
        StaticProofState::SignalOnly,
        "signal_only - Scanner signal only; source-grounded evidence is not recorded",
    ),
    (
        StaticProofState::CodeCited,
        "code_cited - Source-grounded code evidence cited; runtime proof not recorded",
    ),
    (
        StaticProofState::SourceSinkLinked,
        "source_sink_linked - Source and sink are linked in static evidence; runtime proof not recorded",
    ),
    (
        StaticProofState::SanitizerChecked,
        "sanitizer_checked - Static path includes sanitizer checks; runtime proof not recorded",
    ),
    (
        StaticProofState::StaticallyConfirmed,
        "statically_confirmed - Source-grounded and statically confirmed; runtime proof not recorded",
    ),
    (
        StaticProofState::StaticallyRejected,
        "statically_rejected - Static evidence rejected this as vulnerable",
    ),
    (
        StaticProofState::NeedsRuntimeEvidence,
        "needs_runtime_evidence - Static evidence needs runtime verification",
    ),
];

pub fn runtime_validation_label(verification: Option<&PersistedVerification>) -> String {
    let Some(verification) = verification else {
        return "not attempted".to_string();
    };
    match verification.proof_verdict {
        PersistedProofVerdict::Exploited => {
            format!(
                "execution_confirmed - Empirically confirmed at proof level {}",
                verification.proof_level
            )
        }
        PersistedProofVerdict::NotReproduced => {
            "execution_attempted - Runtime verification attempted; exploit was not reproduced"
                .to_string()
        }
        PersistedProofVerdict::HarnessFailedToBuild => {
            "execution_rejected - Verification harness failed to build".to_string()
        }
        PersistedProofVerdict::InfrastructureError => {
            "execution_rejected - Runtime verification was blocked by infrastructure".to_string()
        }
        PersistedProofVerdict::LanguageUnsupportedYet => {
            "execution_rejected - Runtime verification does not support this language yet"
                .to_string()
        }
        PersistedProofVerdict::InsufficientFindingDetail => {
            "execution_rejected - Finding lacks enough detail for runtime verification".to_string()
        }
    }
}

pub(in crate::findings) fn next_action(
    finding: &Finding,
    latest_patch: Option<&PatchResult>,
) -> FindingNextAction {
    [
        patch_next_action(latest_patch),
        verification_next_action(finding),
        rejection_next_action(finding),
        validation_next_action(finding),
    ]
    .into_iter()
    .flatten()
    .next()
    .unwrap_or(FindingNextAction::Review)
}

fn patch_next_action(latest_patch: Option<&PatchResult>) -> Option<FindingNextAction> {
    matches!(
        latest_patch.map(|patch| patch.status),
        Some(PatchStatus::Sound | PatchStatus::Verified)
    )
    .then_some(FindingNextAction::Review)
}

fn verification_next_action(finding: &Finding) -> Option<FindingNextAction> {
    matches!(
        finding.verification.as_ref().map(|v| v.proof_verdict),
        Some(PersistedProofVerdict::Exploited)
    )
    .then_some(FindingNextAction::Patch)
}

fn rejection_next_action(finding: &Finding) -> Option<FindingNextAction> {
    (matches!(
        finding.triage.as_ref().map(|triage| triage.verdict),
        Some(TriageVerdict::FalsePositive | TriageVerdict::ByDesign)
    ) || matches!(
        finding.static_proof_state,
        Some(StaticProofState::StaticallyRejected)
    ))
    .then_some(FindingNextAction::Suppress)
}

fn validation_next_action(finding: &Finding) -> Option<FindingNextAction> {
    (matches!(
        finding.static_proof_state,
        Some(StaticProofState::NeedsRuntimeEvidence | StaticProofState::SourceSinkLinked)
    ) || finding.verification.is_none())
    .then_some(FindingNextAction::Validate)
}

pub(in crate::findings) fn check_state(finding: &Finding) -> &'static str {
    finding
        .triage
        .as_ref()
        .map(|triage| triage.verdict.as_str())
        .unwrap_or("needs_review")
}

pub(in crate::findings) fn location(finding: &Finding) -> String {
    match finding.end_line {
        Some(end) if end != finding.start_line => {
            format!("{}:{}-{}", finding.file_path, finding.start_line, end)
        }
        _ => format!("{}:{}", finding.file_path, finding.start_line),
    }
}

pub(in crate::findings) fn source_label(finding: &Finding) -> &'static str {
    finding
        .vuln_source
        .unwrap_or_else(|| VulnSource::from_tool(&finding.tool))
        .as_str()
}
