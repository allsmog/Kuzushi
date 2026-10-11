use super::*;
use crate::findings::Severity;

fn finding(id: i64) -> Finding {
    let mut finding = Finding::new_tool(
        "audit",
        "rule",
        "src/lib.rs",
        1,
        None,
        Severity::Medium,
        "candidate",
    );
    finding.id = Some(id);
    finding.identity_id = Some("fi_same".to_string());
    finding
}

fn record(
    id: i64,
    finding_id: i64,
    identity: Option<&str>,
    author: TriageAuthor,
) -> ReviewDecisionRecord {
    ReviewDecisionRecord {
        id,
        finding_id,
        identity_id: identity.map(str::to_string),
        decision: ReviewDecision {
            verdict: ReviewDecisionVerdict::RejectedFalsePositive,
            author,
            confidence: 0.8,
            rationale: format!("decision {id}"),
            dismiss_reason: None,
            actor: None,
        },
        triage_verdict: Some(TriageVerdict::FalsePositive),
        created_at: format!("2026-09-08T12:00:{id:02}Z"),
        provenance: None,
    }
}

#[test]
fn local_decision_applies_to_its_identity_bearing_row_only() {
    let findings = [finding(1), finding(2)];
    let records = [record(1, 2, None, TriageAuthor::Auto)];
    let index = EffectiveReviewStateIndex::from_findings_and_decisions(&findings, &records);
    assert!(index.effective_decision_for(&findings[0]).is_none());
    let effective = index
        .effective_decision_for(&findings[1])
        .expect("local decision must remain visible");
    assert_eq!(
        effective.verdict(),
        ReviewDecisionVerdict::RejectedFalsePositive
    );
    assert!(!effective.carried_from_durable_identity());
    assert!(index.verdict_for_identity("fi_same").is_none());
}

#[test]
fn history_includes_local_and_shared_records_without_crossing_rows_or_identities() {
    let selected = finding(2);
    let records = [
        record(1, 1, Some("fi_same"), TriageAuthor::Human),
        record(2, 2, None, TriageAuthor::Auto),
        record(3, 1, None, TriageAuthor::Auto),
        record(4, 2, Some("fi_other"), TriageAuthor::Human),
    ];
    let history = review_decision_history_for(&selected, &records);
    assert_eq!(
        history.iter().map(|record| record.id).collect::<Vec<_>>(),
        [2, 1]
    );
    let wrong_only = EffectiveReviewStateIndex::from_findings_and_decisions(&[], &records[3..]);
    assert!(wrong_only.effective_decision_for(&selected).is_none());
}

#[test]
fn human_priority_and_recency_are_shared_by_local_and_identity_records() {
    let selected = finding(2);
    for (local_author, shared_author, expected) in [
        (TriageAuthor::Human, TriageAuthor::Auto, "decision 1"),
        (TriageAuthor::Auto, TriageAuthor::Human, "decision 2"),
        (TriageAuthor::Auto, TriageAuthor::Auto, "decision 2"),
        (TriageAuthor::Human, TriageAuthor::Human, "decision 2"),
    ] {
        let records = [
            record(1, 2, None, local_author),
            record(2, 1, Some("fi_same"), shared_author),
        ];
        let index = EffectiveReviewStateIndex::from_findings_and_decisions(&[], &records);
        assert_eq!(
            index.effective_decision_for(&selected).unwrap().rationale(),
            expected
        );
        let newer_local = [record(3, 2, None, local_author), records[1].clone()];
        let index = EffectiveReviewStateIndex::from_findings_and_decisions(&[], &newer_local);
        let expected =
            if shared_author == TriageAuthor::Human && local_author != TriageAuthor::Human {
                "decision 2"
            } else {
                "decision 3"
            };
        assert_eq!(
            index.effective_decision_for(&selected).unwrap().rationale(),
            expected
        );
    }
}

fn with_event(mut record: ReviewDecisionRecord, event_seq: u64) -> ReviewDecisionRecord {
    record.provenance = Some(crate::findings::ReviewDecisionProvenance {
        event_seq,
        event_hash: format!("event-{event_seq}"),
        read_watermark: Some(event_seq - 1),
    });
    record
}

#[test]
fn recorded_event_order_survives_a_reversed_display_clock() {
    let selected = finding(2);
    let mut older = with_event(record(1, 1, Some("fi_same"), TriageAuthor::Human), 10);
    older.created_at = "2099-01-01T00:00:00Z".into();
    let newer = with_event(record(2, 2, Some("fi_same"), TriageAuthor::Human), 11);
    let records = [older, newer];
    let index = EffectiveReviewStateIndex::from_findings_and_decisions(&[], &records);

    assert_eq!(
        index.effective_decision_for(&selected).unwrap().rationale(),
        "decision 2"
    );
    assert_eq!(review_decision_history_for(&selected, &records)[0].id, 2);
}

#[test]
fn event_order_is_authoritative_over_projection_ids() {
    let selected = finding(2);
    let records = [
        with_event(record(99, 1, Some("fi_same"), TriageAuthor::Human), 10),
        with_event(record(1, 2, Some("fi_same"), TriageAuthor::Human), 11),
    ];
    let index = EffectiveReviewStateIndex::from_findings_and_decisions(&[], &records);
    assert_eq!(
        index.effective_decision_for(&selected).unwrap().rationale(),
        "decision 1"
    );
}

#[test]
fn embedded_triage_does_not_manufacture_a_newer_human_review() {
    let mut selected = finding(2);
    selected.created_at = "2099-01-01T00:00:00Z".into();
    selected.triaged_by = Some(TriageAuthor::Human);
    selected.triage = Some(crate::findings::TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        confidence: 1.0,
        rationale: "cached old verdict on a newer observation".into(),
        ..Default::default()
    });
    let records = [with_event(
        record(1, 1, Some("fi_same"), TriageAuthor::Human),
        10,
    )];
    let index =
        EffectiveReviewStateIndex::from_findings_and_decisions(&[selected.clone()], &records);
    let decision = index.effective_decision_for(&selected).unwrap();
    assert_eq!(decision.rationale(), "decision 1");
    assert!(decision.carried_from_durable_identity());
}
