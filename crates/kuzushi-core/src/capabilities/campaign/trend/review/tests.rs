use super::*;
use crate::findings::{ReviewDecision, ReviewDecisionVerdict as Verdict, TriageAuthor};

fn record(
    id: i64,
    row: i64,
    identity: Option<&str>,
    verdict: Verdict,
    author: TriageAuthor,
) -> ReviewDecisionRecord {
    ReviewDecisionRecord {
        id,
        finding_id: row,
        identity_id: identity.map(str::to_owned),
        decision: ReviewDecision {
            verdict,
            author,
            confidence: 1.0,
            rationale: "Owned counter fixture".into(),
            dismiss_reason: None,
            actor: None,
        },
        triage_verdict: None,
        created_at: "2026-10-25T00:00:00Z".into(),
        provenance: None,
    }
}

fn subject(row: i64, identity: Option<&str>) -> ReviewDecisionSubject {
    ReviewDecisionSubject {
        finding_id: Some(row),
        identity_id: identity.map(str::to_owned),
    }
}

#[test]
fn later_generation_fp_replaces_confirmation_once_and_clears_cost_ratio() {
    let records = [
        record(
            1,
            11,
            Some("identity-a"),
            Verdict::Confirmed,
            TriageAuthor::Human,
        ),
        record(
            2,
            22,
            Some("identity-a"),
            Verdict::RejectedFalsePositive,
            TriageAuthor::Human,
        ),
    ];
    let metrics = trend_metrics_for_subjects(
        &[subject(22, Some("identity-a"))],
        &records,
        WorkspaceCampaignSpend {
            observed_usd: 2.0,
            provider_spend_unresolved: true,
        },
    );
    assert_eq!(
        (
            metrics.decided_findings,
            metrics.confirmed_findings,
            metrics.rejected_false_positives
        ),
        (1, 0, 1)
    );
    assert_eq!(metrics.fp_rate(), Some(1.0));
    assert_eq!(metrics.cost_per_confirmed_usd(), None);
    assert!(metrics.provider_spend_unresolved);
}

#[test]
fn human_confirmation_carries_to_unreviewed_generation_and_holds_against_machine() {
    let mut automated = record(
        2,
        22,
        Some("identity-a"),
        Verdict::RejectedFalsePositive,
        TriageAuthor::Human,
    );
    automated.decision.author = TriageAuthor::Auto;
    let records = [
        record(
            1,
            11,
            Some("identity-a"),
            Verdict::Confirmed,
            TriageAuthor::Human,
        ),
        automated,
    ];
    let metrics = trend_metrics_for_subjects(
        &[subject(33, Some("identity-a"))],
        &records,
        Default::default(),
    );
    assert_eq!(
        (
            metrics.decided_findings,
            metrics.confirmed_findings,
            metrics.rejected_false_positives
        ),
        (1, 1, 0)
    );
}

#[test]
fn local_decisions_do_not_propagate_or_merge_unknown_identities() {
    let records = [
        record(1, 11, None, Verdict::Confirmed, TriageAuthor::Human),
        record(2, 22, None, Verdict::Deferred, TriageAuthor::Human),
    ];
    let current = trend_metrics_for_subjects(
        &[subject(33, Some("identity-a"))],
        &records,
        Default::default(),
    );
    assert_eq!(current.decided_findings, 0);
    let local = trend_metrics_for_subjects(
        &[subject(11, None), subject(22, None)],
        &records,
        Default::default(),
    );
    assert_eq!((local.decided_findings, local.confirmed_findings), (2, 1));
}

#[test]
fn explicit_reopening_leaves_identity_undecided() {
    let records = [
        record(
            1,
            11,
            Some("identity-a"),
            Verdict::Confirmed,
            TriageAuthor::Human,
        ),
        record(
            2,
            22,
            Some("identity-a"),
            Verdict::NeedsReview,
            TriageAuthor::Human,
        ),
    ];
    let metrics = trend_metrics_for_subjects(
        &[subject(22, Some("identity-a"))],
        &records,
        Default::default(),
    );
    assert_eq!(
        (metrics.decided_findings, metrics.confirmed_findings),
        (0, 0)
    );
    assert_eq!(metrics.fp_rate(), None);
}

#[test]
fn cached_triage_without_a_review_record_does_not_invent_a_decision() {
    let mut row = Finding::new_tool(
        "fixture",
        "owned.marker",
        "owned.rs",
        1,
        None,
        crate::Severity::Low,
        "Owned counter fixture",
    );
    row.id = Some(11);
    row.triaged_by = Some(TriageAuthor::Human);
    row.triage = Some(crate::findings::TriageOutcome {
        verdict: crate::findings::TriageVerdict::TruePositive,
        confidence: 1.0,
        rationale: "Legacy cache without a review event".into(),
        ..Default::default()
    });
    let metrics = trend_metrics_for_findings(&[row], &[], Default::default());
    assert_eq!(
        (metrics.decided_findings, metrics.confirmed_findings),
        (0, 0)
    );
}

#[test]
fn empty_spend_is_not_a_refund_and_keeps_unresolved_consumption_visible() {
    let records = [record(
        1,
        11,
        Some("identity-a"),
        Verdict::Confirmed,
        TriageAuthor::Human,
    )];
    for unresolved in [false, true] {
        let metrics = trend_metrics_for_subjects(
            &[subject(11, Some("identity-a"))],
            &records,
            WorkspaceCampaignSpend {
                observed_usd: -0.0,
                provider_spend_unresolved: unresolved,
            },
        );
        assert!(metrics.strip_label().contains("$0.00 spent"));
        assert!(!metrics.strip_label().contains("$-0.00"));
        assert_eq!(metrics.provider_spend_unresolved, unresolved);
        assert_eq!(metrics.strip_label().contains("incomplete"), unresolved);
    }
}
