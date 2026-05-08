use super::prelude::*;
use super::*;

pub fn proof_state_label(state: Option<StaticProofState>) -> &'static str {
    match state {
        None => "not recorded",
        Some(StaticProofState::SignalOnly) => {
            "signal_only - Scanner signal only; source-grounded evidence is not recorded"
        }
        Some(StaticProofState::CodeCited) => {
            "code_cited - Source-grounded code evidence cited, not empirically validated"
        }
        Some(StaticProofState::SourceSinkLinked) => {
            "source_sink_linked - Source and sink are linked in static evidence, not empirically validated"
        }
        Some(StaticProofState::SanitizerChecked) => {
            "sanitizer_checked - Static path includes sanitizer checks, not empirically validated"
        }
        Some(StaticProofState::StaticallyConfirmed) => {
            "statically_confirmed - Source-grounded and statically confirmed, not empirically validated"
        }
        Some(StaticProofState::StaticallyRejected) => {
            "statically_rejected - Static evidence rejected this as vulnerable"
        }
        Some(StaticProofState::NeedsRuntimeEvidence) => {
            "needs_runtime_evidence - Static evidence needs runtime validation"
        }
    }
}

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
            "execution_attempted - Runtime validation attempted; exploit was not reproduced"
                .to_string()
        }
        PersistedProofVerdict::HarnessFailedToBuild => {
            "execution_rejected - Validation harness failed to build".to_string()
        }
        PersistedProofVerdict::InfrastructureError => {
            "execution_rejected - Runtime validation was blocked by infrastructure".to_string()
        }
        PersistedProofVerdict::LanguageUnsupportedYet => {
            "execution_rejected - Runtime validation does not support this language yet".to_string()
        }
        PersistedProofVerdict::InsufficientFindingDetail => {
            "execution_rejected - Finding lacks enough detail for runtime validation".to_string()
        }
    }
}

pub(in crate::findings) fn next_action(
    finding: &Finding,
    latest_patch: Option<&PatchResult>,
) -> FindingNextAction {
    if matches!(
        latest_patch.map(|patch| patch.status),
        Some(PatchStatus::Sound | PatchStatus::Verified)
    ) {
        return FindingNextAction::Review;
    }
    if matches!(
        finding.verification.as_ref().map(|v| v.proof_verdict),
        Some(PersistedProofVerdict::Exploited)
    ) {
        return FindingNextAction::Patch;
    }
    if matches!(
        finding.triage.as_ref().map(|triage| triage.verdict),
        Some(TriageVerdict::FalsePositive | TriageVerdict::ByDesign)
    ) || matches!(
        finding.static_proof_state,
        Some(StaticProofState::StaticallyRejected)
    ) {
        return FindingNextAction::Suppress;
    }
    if matches!(
        finding.static_proof_state,
        Some(StaticProofState::NeedsRuntimeEvidence | StaticProofState::SourceSinkLinked)
    ) || finding.verification.is_none()
    {
        return FindingNextAction::Validate;
    }
    FindingNextAction::Review
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
