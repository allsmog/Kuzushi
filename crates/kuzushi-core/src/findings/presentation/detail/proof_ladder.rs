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
    RuntimeVerified,
    PathLinked,
    SourceGrounded,
    Rejected,
    Suspected,
}

impl ProofLadderKind {
    /// Coarse confidence band for this ladder rung. The single mapping from the
    /// rich 6-way ladder down to the operator-facing 4-band axis. `Patched` maps
    /// to `Confirmed` here, but `ProofConfidence::classify` never produces a
    /// `Patched` rung in practice — see that method's doc comment.
    pub(in crate::findings) fn confidence(self) -> ProofConfidence {
        match self {
            Self::Patched | Self::RuntimeVerified => ProofConfidence::Confirmed,
            Self::PathLinked | Self::SourceGrounded => ProofConfidence::Likely,
            Self::Rejected => ProofConfidence::Dismissed,
            Self::Suspected => ProofConfidence::Unverified,
        }
    }
}

impl ProofConfidence {
    /// Single canonical classifier. Delegates to the same predicate helpers the
    /// proof ladder uses, so the confidence chip can never disagree with the
    /// ladder or lifecycle status. A suppressed finding short-circuits to
    /// `Dismissed`, mirroring `finding_lifecycle_status`'s suppressed short-cut.
    ///
    /// Patch-blind by construction: `Finding` has no patch field, so this always
    /// resolves the ladder with `latest_patch: None`. `Confirmed` therefore means
    /// runtime-exploited only — it never reflects a verified patch. Reaching the
    /// ladder's `Patched` rung requires a caller with real `PatchResult` data,
    /// such as `proof_ladder_state` (finding-detail rendering); the chip/exports
    /// this classifier feeds do not carry that data today.
    pub fn classify(finding: &Finding) -> Self {
        if finding.suppressed {
            return Self::Dismissed;
        }
        proof_ladder_kind(finding, None).confidence()
    }
}

fn proof_ladder_kind(finding: &Finding, latest_patch: Option<&PatchResult>) -> ProofLadderKind {
    [
        patched_ladder_kind(latest_patch),
        runtime_verified_ladder_kind(finding),
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

fn runtime_verified_ladder_kind(finding: &Finding) -> Option<ProofLadderKind> {
    matches!(
        finding.verification.as_ref().map(|v| v.proof_verdict),
        Some(PersistedProofVerdict::Exploited)
    )
    .then_some(ProofLadderKind::RuntimeVerified)
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

#[cfg(test)]
mod confidence_tests {
    use super::*;
    use crate::findings::domain::{
        PersistedProofVerdict, PersistedSandboxBackend, PersistedVerification, TriageOutcome,
        TriageVerdict,
    };

    fn exploited_verification() -> PersistedVerification {
        PersistedVerification {
            proof_level: 3,
            proof_verdict: PersistedProofVerdict::Exploited,
            backend: PersistedSandboxBackend::Plain,
            language: None,
            harness_path: None,
            crash_evidence: None,
            duration_ms: 0,
            cost_usd: 0.0,
            notes: Vec::new(),
            created_at: String::new(),
        }
    }

    fn finding_with_static(state: StaticProofState) -> Finding {
        Finding {
            static_proof_state: Some(state),
            ..Finding::default()
        }
    }

    #[test]
    fn default_finding_is_unverified() {
        assert_eq!(
            ProofConfidence::classify(&Finding::default()),
            ProofConfidence::Unverified
        );
    }

    #[test]
    fn runtime_exploited_is_confirmed() {
        let finding = Finding {
            verification: Some(exploited_verification()),
            ..Finding::default()
        };
        assert_eq!(
            ProofConfidence::classify(&finding),
            ProofConfidence::Confirmed
        );
    }

    #[test]
    fn suppressed_is_dismissed_even_when_exploited() {
        let finding = Finding {
            verification: Some(exploited_verification()),
            suppressed: true,
            ..Finding::default()
        };
        assert_eq!(
            ProofConfidence::classify(&finding),
            ProofConfidence::Dismissed
        );
    }

    #[test]
    fn static_states_map_through_the_ladder() {
        let cases = [
            (StaticProofState::SignalOnly, ProofConfidence::Unverified),
            (StaticProofState::CodeCited, ProofConfidence::Likely),
            (StaticProofState::SourceSinkLinked, ProofConfidence::Likely),
            (StaticProofState::SanitizerChecked, ProofConfidence::Likely),
            (
                StaticProofState::StaticallyConfirmed,
                ProofConfidence::Likely,
            ),
            (
                StaticProofState::StaticallyRejected,
                ProofConfidence::Dismissed,
            ),
            (
                StaticProofState::NeedsRuntimeEvidence,
                ProofConfidence::Unverified,
            ),
        ];
        for (state, expected) in cases {
            assert_eq!(
                ProofConfidence::classify(&finding_with_static(state)),
                expected,
                "static state {state:?}"
            );
        }
    }

    #[test]
    fn triage_false_positive_is_dismissed() {
        let finding = Finding {
            triage: Some(TriageOutcome {
                verdict: TriageVerdict::FalsePositive,
                ..TriageOutcome::default()
            }),
            ..Finding::default()
        };
        assert_eq!(
            ProofConfidence::classify(&finding),
            ProofConfidence::Dismissed
        );
    }

    #[test]
    fn classify_never_disagrees_with_the_ladder() {
        // The chip is derived from the same predicate chain as the ladder, so a
        // `Confirmed`/`Dismissed` chip must correspond to a confirmed/rejected
        // ladder rung for every static state.
        for state in [
            StaticProofState::SignalOnly,
            StaticProofState::CodeCited,
            StaticProofState::SourceSinkLinked,
            StaticProofState::SanitizerChecked,
            StaticProofState::StaticallyConfirmed,
            StaticProofState::StaticallyRejected,
            StaticProofState::NeedsRuntimeEvidence,
        ] {
            let finding = finding_with_static(state);
            let ladder = proof_ladder_kind(&finding, None);
            assert_eq!(ProofConfidence::classify(&finding), ladder.confidence());
        }
    }
}
