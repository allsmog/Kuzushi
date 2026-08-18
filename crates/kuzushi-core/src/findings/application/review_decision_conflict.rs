use super::super::domain::{
    Finding, PersistedProofVerdict, PersistedVerification, ReviewDecisionVerdict,
};
use super::super::presentation::finding_lifecycle_status;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewDecisionConflict {
    RuntimeVerifiedAfterRejection,
    ReappearedAfterRejection,
    NotReproducedAfterConfirmation,
}

impl ReviewDecisionConflict {
    pub fn classify(
        finding: &Finding,
        verdict: ReviewDecisionVerdict,
        carried_from_durable_identity: bool,
    ) -> Option<Self> {
        if !carried_from_durable_identity {
            return None;
        }
        match verdict {
            ReviewDecisionVerdict::RejectedFalsePositive => rejection_conflict(finding),
            ReviewDecisionVerdict::Confirmed | ReviewDecisionVerdict::ToFix => {
                confirmed_conflict(finding)
            }
            _ => None,
        }
    }

    pub const fn export_token(self) -> &'static str {
        match self {
            Self::RuntimeVerifiedAfterRejection => "runtime_verified_after_rejection",
            Self::ReappearedAfterRejection => "reappeared_after_rejection",
            Self::NotReproducedAfterConfirmation => "not_reproduced_after_confirmation",
        }
    }
}

fn rejection_conflict(finding: &Finding) -> Option<ReviewDecisionConflict> {
    if finding
        .verification
        .as_ref()
        .is_some_and(PersistedVerification::is_empirically_verified)
    {
        return Some(ReviewDecisionConflict::RuntimeVerifiedAfterRejection);
    }
    active_scanner_signal(finding).then_some(ReviewDecisionConflict::ReappearedAfterRejection)
}

fn confirmed_conflict(finding: &Finding) -> Option<ReviewDecisionConflict> {
    finding
        .verification
        .as_ref()
        .is_some_and(|verification| {
            verification.proof_verdict == PersistedProofVerdict::NotReproduced
        })
        .then_some(ReviewDecisionConflict::NotReproducedAfterConfirmation)
}

fn active_scanner_signal(finding: &Finding) -> bool {
    matches!(
        finding_lifecycle_status(finding),
        "candidate"
            | "seen"
            | "statically_supported"
            | "verified_static"
            | "needs_runtime_evidence"
            | "runtime_verified"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::StaticProofState;

    fn carried_conflict(
        finding: &Finding,
        verdict: ReviewDecisionVerdict,
    ) -> Option<ReviewDecisionConflict> {
        ReviewDecisionConflict::classify(finding, verdict, true)
    }

    #[test]
    fn rejection_distinguishes_runtime_refutation_from_scanner_reappearance() {
        let mut finding = Finding::default();
        finding.static_proof_state = Some(StaticProofState::SourceSinkLinked);
        assert_eq!(
            carried_conflict(&finding, ReviewDecisionVerdict::RejectedFalsePositive),
            Some(ReviewDecisionConflict::ReappearedAfterRejection)
        );

        finding.verification = Some(crate::findings::test_support::empirically_verified(3));
        assert_eq!(
            carried_conflict(&finding, ReviewDecisionVerdict::RejectedFalsePositive),
            Some(ReviewDecisionConflict::RuntimeVerifiedAfterRejection)
        );
    }

    #[test]
    fn failed_reproduction_reopens_a_carried_confirmation() {
        let mut finding = Finding::default();
        let mut verification = crate::findings::test_support::empirically_verified(2);
        verification.proof_verdict = PersistedProofVerdict::NotReproduced;
        finding.verification = Some(verification);

        assert_eq!(
            carried_conflict(&finding, ReviewDecisionVerdict::Confirmed),
            Some(ReviewDecisionConflict::NotReproducedAfterConfirmation)
        );
        assert_eq!(
            carried_conflict(&finding, ReviewDecisionVerdict::ToFix),
            Some(ReviewDecisionConflict::NotReproducedAfterConfirmation)
        );
    }

    #[test]
    fn current_observation_decisions_do_not_conflict_with_themselves() {
        let mut finding = Finding::default();
        finding.verification = Some(crate::findings::test_support::empirically_verified(1));

        assert_eq!(
            ReviewDecisionConflict::classify(
                &finding,
                ReviewDecisionVerdict::RejectedFalsePositive,
                false,
            ),
            None
        );
    }
}
