use super::*;
use crate::findings::test_support::ReviewedFindingFixture;
use crate::findings::{ReviewDecisionVerdict, TriageAuthor, TriageVerdict};

fn candidate(fixture: &ReviewedFindingFixture) -> PatchCandidateLookup {
    let finding = fixture.finding();
    let gate = crate::findings::load_finding_review_gate(&fixture.store, &finding).unwrap();
    patch_candidate_for_gate(finding, gate)
}

fn refusal(lookup: PatchCandidateLookup) -> Value {
    match lookup {
        PatchCandidateLookup::Refused(response) => response,
        PatchCandidateLookup::Ready(_) => panic!("expected patch:finding to refuse"),
    }
}

#[test]
fn human_confirmed_finding_without_triage_is_a_patch_candidate() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_human_decision(ReviewDecisionVerdict::Confirmed);

    let PatchCandidateLookup::Ready(candidate) = candidate(&fixture) else {
        panic!("a human-confirmed finding must be patchable");
    };
    let ReviewConfirmation::ReviewDecision(decision) = candidate.confirmation else {
        panic!("a human confirmation must not be relabelled as automated triage");
    };
    assert_eq!(decision.author, TriageAuthor::Human);
}

#[test]
fn human_rejection_overrides_automated_true_positive() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_auto_triage(TriageVerdict::TruePositive);
    fixture.record_human_decision(ReviewDecisionVerdict::RejectedFalsePositive);

    let response = refusal(candidate(&fixture));

    assert_eq!(response["data"]["reason"], json!("not-confirmed-true-positive"));
    assert_eq!(
        response["data"]["reviewDecision"],
        json!("rejected_false_positive")
    );
    assert_eq!(response["data"]["reviewAuthor"], json!("human"));
    assert!(response["output"].as_str().unwrap().contains(
        "is not confirmed true_positive (review decision in force: rejected_false_positive by human)"
    ));
}

#[test]
fn automated_true_positive_keeps_its_triage_outcome() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_auto_triage(TriageVerdict::TruePositive);

    let PatchCandidateLookup::Ready(candidate) = candidate(&fixture) else {
        panic!("an automated true positive must stay patchable");
    };
    assert!(matches!(
        candidate.confirmation,
        ReviewConfirmation::AutomatedTriage(_)
    ));
}

#[test]
fn unreviewed_finding_refuses_with_both_remedies() {
    let fixture = ReviewedFindingFixture::new();

    let response = refusal(candidate(&fixture));

    assert_eq!(response["data"]["reason"], json!("missing-triage"));
    assert!(response["output"].as_str().unwrap().contains(
        "has no triage verdict and no confirming review decision. Run triage:run first, or record a confirmed or to_fix review decision."
    ));
}
