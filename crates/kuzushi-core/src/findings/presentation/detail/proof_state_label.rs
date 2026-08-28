use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticProofSummary {
    pub label: &'static str,
    pub explanation: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeValidationSummary {
    pub label: String,
    pub explanation: &'static str,
}

pub fn proof_state_label(state: Option<StaticProofState>) -> &'static str {
    state
        .and_then(proof_state_recorded_label)
        .unwrap_or("not recorded")
}

pub fn finding_lifecycle_status(finding: &Finding) -> &'static str {
    if finding.suppressed {
        return "suppressed";
    }
    if finding.snoozed_until.is_some() {
        return "snoozed";
    }
    proof_lifecycle_status(finding).unwrap_or_else(|| run_lifecycle_status(finding))
}

fn proof_lifecycle_status(finding: &Finding) -> Option<&'static str> {
    finding
        .verification
        .as_ref()
        .filter(|verification| !verification.is_model_assessment())
        .map(verification_lifecycle_label)
        .or_else(|| {
            finding
                .static_proof_state
                .filter(|state| {
                    !matches!(
                        state,
                        StaticProofState::SignalOnly | StaticProofState::NeedsRuntimeEvidence
                    )
                })
                .map(static_lifecycle_label)
        })
        .or_else(|| {
            finding
                .verification
                .as_ref()
                .filter(|verification| verification.is_model_assessment())
                .map(|_| "model_assessed")
        })
        .or_else(|| finding.static_proof_state.map(static_lifecycle_label))
}

fn run_lifecycle_status(finding: &Finding) -> &'static str {
    if finding
        .scan_id
        .as_ref()
        .is_some_and(|scan_id| !scan_id.is_empty())
    {
        "seen"
    } else {
        "candidate"
    }
}

fn verification_lifecycle_label(verification: &PersistedVerification) -> &'static str {
    match verification.proof_verdict {
        PersistedProofVerdict::NotAttempted => "needs_runtime_evidence",
        PersistedProofVerdict::Exploited => "runtime_verified",
        PersistedProofVerdict::NotReproduced => "runtime_not_reproduced",
        PersistedProofVerdict::HarnessFailedToBuild => "verification_build_failed",
        PersistedProofVerdict::InfrastructureError => "verification_infra_error",
        PersistedProofVerdict::LanguageUnsupportedYet => "verification_unsupported",
        PersistedProofVerdict::InsufficientFindingDetail => "needs_detail",
    }
}

fn static_lifecycle_label(state: StaticProofState) -> &'static str {
    match state {
        StaticProofState::StaticallyConfirmed => "verified_static",
        StaticProofState::StaticallyRejected => "statically_rejected",
        StaticProofState::NeedsRuntimeEvidence => "needs_runtime_evidence",
        StaticProofState::CodeCited
        | StaticProofState::SourceSinkLinked
        | StaticProofState::SanitizerChecked => "statically_supported",
        StaticProofState::SignalOnly => "candidate",
    }
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
        "statically_confirmed - Strong static evidence supports the scanner claim; runtime proof not recorded",
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

pub fn static_proof_summary(state: Option<StaticProofState>) -> StaticProofSummary {
    state
        .and_then(static_proof_recorded_summary)
        .unwrap_or(StaticProofSummary {
            label: "not recorded",
            explanation: "no static proof recorded",
        })
}

fn static_proof_recorded_summary(state: StaticProofState) -> Option<StaticProofSummary> {
    STATIC_PROOF_SUMMARIES
        .iter()
        .find_map(|(candidate, summary)| (*candidate == state).then_some(*summary))
}

const STATIC_PROOF_SUMMARIES: &[(StaticProofState, StaticProofSummary)] = &[
    (
        StaticProofState::SignalOnly,
        StaticProofSummary {
            label: "signal-only",
            explanation: "scanner signal only; no source-grounded evidence recorded",
        },
    ),
    (
        StaticProofState::CodeCited,
        StaticProofSummary {
            label: "code-cited",
            explanation: "source-grounded code evidence cited",
        },
    ),
    (
        StaticProofState::SourceSinkLinked,
        StaticProofSummary {
            label: "path-linked",
            explanation: "static evidence links source to sink",
        },
    ),
    (
        StaticProofState::SanitizerChecked,
        StaticProofSummary {
            label: "path-linked",
            explanation: "static path includes sanitizer assessment",
        },
    ),
    (
        StaticProofState::StaticallyConfirmed,
        StaticProofSummary {
            label: "static-supported",
            explanation: "strong static evidence supports the scanner claim",
        },
    ),
    (
        StaticProofState::StaticallyRejected,
        StaticProofSummary {
            label: "static-no",
            explanation: "static evidence rejects the scanner claim",
        },
    ),
    (
        StaticProofState::NeedsRuntimeEvidence,
        StaticProofSummary {
            label: "needs-runtime",
            explanation: "static evidence needs runtime verification",
        },
    ),
];

/// Human-readable runtime-validation label, exported verbatim into JSON/JSONL
/// exports and the finding detail report.
///
/// The four non-disproof verdicts below (harness failed to build, blocked
/// infrastructure, unsupported language, insufficient detail) say only that
/// runtime verification could not execute — they carry no verdict on the
/// scanner's claim. Their prefix therefore reads `not executed`, not
/// `execution_rejected`, which reads as "we rejected the claim".
/// `execution_rejected` remains the durable artifact vocabulary (see
/// `findings::domain::static_proof_state::is_runtime_proof_state`); only this
/// operator-facing prefix changed.
pub fn runtime_validation_label(verification: Option<&PersistedVerification>) -> String {
    let Some(verification) = verification else {
        return "not attempted".to_string();
    };
    if verification.is_model_assessment() {
        return "model_assessed - automated review only; runtime verification was not attempted"
            .to_string();
    }
    match verification.proof_verdict {
        PersistedProofVerdict::NotAttempted => {
            "not_attempted - Runtime verification did not execute target code".to_string()
        }
        PersistedProofVerdict::Exploited => {
            format!(
                "runtime_verified - empirical verification evidence recorded at proof level {}",
                verification.proof_level
            )
        }
        PersistedProofVerdict::NotReproduced => {
            "runtime_attempted - runtime verification did not reproduce the scanner claim"
                .to_string()
        }
        PersistedProofVerdict::HarnessFailedToBuild => {
            "not executed - Verification harness failed to build".to_string()
        }
        PersistedProofVerdict::InfrastructureError => {
            "not executed - Runtime verification was blocked by infrastructure".to_string()
        }
        PersistedProofVerdict::LanguageUnsupportedYet => {
            "not executed - Runtime verification does not support this language yet"
                .to_string()
        }
        PersistedProofVerdict::InsufficientFindingDetail => {
            "not executed - Finding lacks enough detail for runtime verification".to_string()
        }
    }
}

pub fn runtime_validation_summary(
    verification: Option<&PersistedVerification>,
) -> RuntimeValidationSummary {
    let Some(verification) = verification else {
        return runtime_summary("not verified", "runtime verification has not run");
    };
    if verification.is_model_assessment() {
        return runtime_summary(
            "model assessed",
            "automated review assessed exploitability without executing target code",
        );
    }
    if verification.is_empirically_verified() {
        return RuntimeValidationSummary {
            label: format!("verified L{}", verification.proof_level),
            explanation: "runtime verification recorded empirical evidence for this finding",
        };
    }
    runtime_verdict_summary(verification.proof_verdict)
        .unwrap_or_else(|| runtime_summary("not verified", "runtime verification has not run"))
}

fn runtime_verdict_summary(verdict: PersistedProofVerdict) -> Option<RuntimeValidationSummary> {
    RUNTIME_VALIDATION_SUMMARIES
        .iter()
        .find_map(|(candidate, label, explanation)| {
            (*candidate == verdict).then(|| runtime_summary(*label, *explanation))
        })
}

fn runtime_summary(label: &str, explanation: &'static str) -> RuntimeValidationSummary {
    RuntimeValidationSummary {
        label: label.to_string(),
        explanation,
    }
}

const RUNTIME_VALIDATION_SUMMARIES: &[(PersistedProofVerdict, &str, &str)] = &[
    (
        PersistedProofVerdict::NotAttempted,
        "not attempted",
        "runtime verification did not execute target code",
    ),
    (
        PersistedProofVerdict::NotReproduced,
        "not reproduced",
        "runtime verification did not reproduce the scanner claim",
    ),
    (
        PersistedProofVerdict::HarnessFailedToBuild,
        "verify-build",
        "verification harness failed to build",
    ),
    (
        PersistedProofVerdict::InfrastructureError,
        "verify-infra",
        "runtime verification was blocked by infrastructure",
    ),
    (
        PersistedProofVerdict::LanguageUnsupportedYet,
        "unsupported",
        "runtime verification does not support this language",
    ),
    (
        PersistedProofVerdict::InsufficientFindingDetail,
        "needs-detail",
        "finding lacks enough detail for verification",
    ),
];

pub fn finding_next_action(
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
    finding
        .verification
        .as_ref()
        .is_some_and(PersistedVerification::is_empirically_verified)
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
    ) || !finding
        .verification
        .as_ref()
        .is_some_and(PersistedVerification::has_terminal_runtime_verification))
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
