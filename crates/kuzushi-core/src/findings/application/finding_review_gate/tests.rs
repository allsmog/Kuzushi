use super::*;
use crate::findings::test_support::ReviewedFindingFixture;
use crate::findings::{DismissReason, ReviewDecisionVerdict};

fn gate(fixture: &ReviewedFindingFixture) -> FindingReviewGate {
    load_finding_review_gate(&fixture.store, &fixture.finding()).unwrap()
}

#[test]
fn finding_without_triage_or_decision_is_unreviewed() {
    let fixture = ReviewedFindingFixture::new();

    assert_eq!(gate(&fixture), FindingReviewGate::Unreviewed);
}

#[test]
fn human_confirmation_without_triage_confirms_as_a_review_decision() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_human_decision(ReviewDecisionVerdict::Confirmed);

    let FindingReviewGate::Confirmed(ReviewConfirmation::ReviewDecision(decision)) = gate(&fixture)
    else {
        panic!("expected a human review confirmation, got {:?}", gate(&fixture));
    };
    assert_eq!(decision.author, TriageAuthor::Human);
    assert_eq!(decision.verdict, ReviewDecisionVerdict::Confirmed);
}

#[test]
fn automated_true_positive_confirms_with_its_own_triage_outcome() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_auto_triage(TriageVerdict::TruePositive);

    let FindingReviewGate::Confirmed(ReviewConfirmation::AutomatedTriage(triage)) = gate(&fixture)
    else {
        panic!("expected automated triage confirmation, got {:?}", gate(&fixture));
    };
    assert_eq!(triage.rationale, "automated triage");
}

#[test]
fn human_rejection_overrides_automated_true_positive() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_auto_triage(TriageVerdict::TruePositive);
    fixture.record_human_decision(ReviewDecisionVerdict::RejectedFalsePositive);

    let FindingReviewGate::ReviewerDismissed(decision) = gate(&fixture) else {
        panic!("expected a reviewer dismissal, got {:?}", gate(&fixture));
    };
    assert_eq!(
        decision.effective_dismiss_reason(),
        Some(DismissReason::FalsePositive)
    );
}

#[test]
fn human_confirmation_overrides_automated_false_positive() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_auto_triage(TriageVerdict::FalsePositive);
    fixture.record_human_decision(ReviewDecisionVerdict::ToFix);

    assert!(matches!(
        gate(&fixture),
        FindingReviewGate::Confirmed(ReviewConfirmation::ReviewDecision(_))
    ));
}

#[test]
fn automated_false_positive_is_unconfirmed_not_a_reviewer_dismissal() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_auto_triage(TriageVerdict::FalsePositive);

    assert!(matches!(
        gate(&fixture),
        FindingReviewGate::Unconfirmed(ReviewDecision {
            verdict: ReviewDecisionVerdict::RejectedFalsePositive,
            author: TriageAuthor::Auto,
            ..
        })
    ));
}

#[test]
fn human_needs_review_without_triage_is_unconfirmed() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_human_decision(ReviewDecisionVerdict::NeedsReview);

    assert!(matches!(
        gate(&fixture),
        FindingReviewGate::Unconfirmed(ReviewDecision {
            author: TriageAuthor::Human,
            ..
        })
    ));
}
