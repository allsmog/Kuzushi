use super::*;
use crate::findings::{ReviewDecisionVerdict, TriageAuthor, TriageOutcome};

fn decision(verdict: ReviewDecisionVerdict) -> ReviewDecision {
    ReviewDecision {
        verdict,
        author: TriageAuthor::Human,
        confidence: 1.0,
        rationale: "Owned operator decision".into(),
        dismiss_reason: None,
        actor: Some("operator".into()),
    }
}

#[test]
fn confirmation_retains_its_real_authority() {
    let confirmation =
        ReviewConfirmation::ReviewDecision(decision(ReviewDecisionVerdict::Confirmed));
    assert_eq!(
        variant_confirmation(
            "variant:lift-pattern",
            "owned",
            FindingReviewGate::Confirmed(confirmation.clone())
        )
        .unwrap(),
        confirmation
    );
    let confirmation = ReviewConfirmation::AutomatedTriage(TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        ..Default::default()
    });
    assert_eq!(
        variant_confirmation(
            "variant:hunt",
            "owned",
            FindingReviewGate::Confirmed(confirmation.clone())
        )
        .unwrap(),
        confirmation
    );
}

#[test]
fn unreviewed_and_rejected_subjects_keep_compatible_refusal_fields() {
    for tool in ["variant:hunt", "variant:lift-pattern"] {
        let result =
            variant_confirmation(tool, "owned", FindingReviewGate::Unreviewed).unwrap_err();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["data"]["reason"], "missing-triage");
        assert!(result["output"].as_str().unwrap().starts_with(tool));
        for gate in [
            FindingReviewGate::ReviewerDismissed(decision(
                ReviewDecisionVerdict::RejectedFalsePositive,
            )),
            FindingReviewGate::Unconfirmed(decision(ReviewDecisionVerdict::Deferred)),
        ] {
            let result = variant_confirmation(tool, "owned", gate).unwrap_err();
            assert_eq!(result["data"]["reason"], "non-true-positive");
            assert_eq!(result["data"]["reviewAuthor"], "human");
        }
    }
}
