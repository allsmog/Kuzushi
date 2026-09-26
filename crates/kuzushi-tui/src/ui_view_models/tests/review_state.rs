use super::*;
use crate::ui_view_models::review_conflicts::effective_review_decision_conflict_label;
use kuzushi_core::findings::{
    ReviewDecision, ReviewDecisionRecord, ReviewDecisionVerdict, TriageAuthor,
};
use kuzushi_core::{Finding, Severity, StaticProofState, TriageOutcome, TriageVerdict};

#[test]
fn review_state_separates_terminal_decisions_from_needs_review() {
    let mut finding = Finding::new_tool(
        "semgrep",
        "demo.rule",
        "src/lib.rs",
        12,
        None,
        Severity::High,
        "candidate",
    );
    assert_eq!(review_decision_label(&finding), "needs_review");
    assert!(!review_decision_complete(&finding));
    assert_eq!(review_confidence_label(&finding), "-");
    assert_eq!(review_author_label(&finding), "-");

    finding.triage = Some(TriageOutcome {
        first_link: None,
        refute_reason: None,
        verdict: TriageVerdict::ByDesign,
        confidence: 0.71,
        rationale: "accepted by owner".to_string(),
        cost_usd: 0.0,
        cost_usd_exact: true,
        estimated_cost_usd: None,
    });

    assert_eq!(review_decision_label(&finding), "accepted_risk");
    assert!(review_decision_complete(&finding));
    assert_eq!(review_confidence_label(&finding), "71%");
    assert_eq!(review_author_label(&finding), "auto");
}

#[test]
fn lifecycle_and_evidence_labels_use_recorded_finding_state() {
    let mut finding = Finding::new_tool(
        "semgrep",
        "demo.rule",
        "src/lib.rs",
        12,
        None,
        Severity::Medium,
        "candidate",
    );
    assert_eq!(lifecycle_status_label(&finding), "candidate");
    assert_eq!(evidence_state_label(&finding), "source-linked");

    finding.scan_id = Some("run-1".to_string());
    finding.static_proof_state = Some(StaticProofState::SourceSinkLinked);
    finding.corroboration_count = 2;

    assert_eq!(lifecycle_status_label(&finding), "statically_supported");
    assert_eq!(evidence_state_label(&finding), "multiple observations");
}

#[test]
fn effective_review_index_uses_loaded_durable_identity_decision() {
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let mut reviewed = finding("demo.reviewed", 12, "reviewed row");
    reviewed.id = Some(1);
    reviewed.created_at = "2026-07-01T00:00:00Z".to_string();
    reviewed.identity_id = Some(identity_id.clone());
    reviewed.triage = Some(TriageOutcome {
        first_link: None,
        refute_reason: None,
        verdict: TriageVerdict::TruePositive,
        confidence: 0.91,
        rationale: "operator confirmed".to_string(),
        cost_usd: 0.0,
        cost_usd_exact: true,
        estimated_cost_usd: None,
    });
    reviewed.triaged_by = Some(TriageAuthor::Human);

    let mut rerun = finding("demo.rerun", 18, "same durable finding seen later");
    rerun.id = Some(2);
    rerun.identity_id = Some(identity_id);

    let index =
        EffectiveReviewStateIndex::from_findings_and_decisions(&[reviewed, rerun.clone()], &[]);
    let decision = index
        .effective_decision_for(&rerun)
        .expect("identity decision");

    assert_eq!(decision.decision_label(), "confirmed");
    assert_eq!(decision.confidence_label(), "91%");
    assert_eq!(decision.author_label(), "human");
    assert_eq!(decision.source_label(), "durable identity");
    assert!(decision.complete());
    assert!(rerun.triage.is_none());
}

#[test]
fn effective_review_index_prefers_loaded_append_only_decisions() {
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let mut reviewed = finding("demo.reviewed", 12, "reviewed row");
    reviewed.id = Some(1);
    reviewed.identity_id = Some(identity_id.clone());

    let mut rerun = finding("demo.rerun", 18, "same durable finding seen later");
    rerun.id = Some(2);
    rerun.identity_id = Some(identity_id.clone());

    let record = ReviewDecisionRecord {
        id: 7,
        finding_id: 1,
        identity_id: Some(identity_id),
        decision: ReviewDecision {
            verdict: ReviewDecisionVerdict::Suppressed,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: "suppressed by approved review policy".to_string(),
            dismiss_reason: None,
            actor: None,
        },
        triage_verdict: None,
        created_at: "2026-07-02T00:00:00Z".to_string(),
        provenance: None,
    };

    let index = EffectiveReviewStateIndex::from_findings_and_decisions(
        &[reviewed, rerun.clone()],
        &[record],
    );
    let decision = index
        .effective_decision_for(&rerun)
        .expect("identity decision");

    assert_eq!(decision.decision_label(), "suppressed");
    assert_eq!(decision.triage_verdict_label(), None);
    assert_eq!(decision.source_label(), "durable identity");
    assert!(decision.complete());
    assert!(rerun.triage.is_none());
}

#[test]
fn human_identity_decision_dominates_a_newer_automatic_decision() {
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let mut rerun = finding("demo.rerun", 18, "same durable finding seen later");
    rerun.id = Some(2);
    rerun.created_at = "2026-07-03T00:00:00Z".to_string();
    rerun.identity_id = Some(identity_id.clone());
    rerun.triage = Some(TriageOutcome {
        verdict: TriageVerdict::FalsePositive,
        confidence: 0.95,
        rationale: "newer automated review disagreed".to_string(),
        ..TriageOutcome::default()
    });
    rerun.triaged_by = Some(TriageAuthor::Auto);

    let human = ReviewDecisionRecord {
        id: 7,
        finding_id: 1,
        identity_id: Some(identity_id.clone()),
        decision: ReviewDecision {
            verdict: ReviewDecisionVerdict::Confirmed,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: "operator confirmed the source".to_string(),
            dismiss_reason: None,
            actor: Some("operator".to_string()),
        },
        triage_verdict: Some(TriageVerdict::TruePositive),
        created_at: "2026-07-01T00:00:00Z".to_string(),
        provenance: None,
    };
    let automatic = ReviewDecisionRecord {
        id: 8,
        finding_id: 2,
        identity_id: Some(identity_id),
        decision: ReviewDecision {
            verdict: ReviewDecisionVerdict::RejectedFalsePositive,
            author: TriageAuthor::Auto,
            confidence: 0.95,
            rationale: "newer automated review disagreed".to_string(),
            dismiss_reason: None,
            actor: None,
        },
        triage_verdict: Some(TriageVerdict::FalsePositive),
        created_at: "2026-07-03T00:00:00Z".to_string(),
        provenance: None,
    };

    let records = vec![human, automatic];
    let index = EffectiveReviewStateIndex::from_findings_and_decisions(
        std::slice::from_ref(&rerun),
        &records,
    );
    let decision = index
        .effective_decision_for(&rerun)
        .expect("human decision");

    assert_eq!(decision.decision_label(), "confirmed");
    assert_eq!(decision.author_label(), "human");
    assert_eq!(decision.rationale(), "operator confirmed the source");
    assert_eq!(decision.source_label(), "durable identity");
    assert_eq!(review_decision_history_for(&rerun, &records).len(), 2);
}

#[test]
fn carried_rejected_decision_conflicts_with_new_scanner_signal() {
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let mut reviewed = finding("demo.reviewed", 12, "reviewed row");
    reviewed.id = Some(1);
    reviewed.identity_id = Some(identity_id.clone());
    reviewed.triage = Some(TriageOutcome {
        first_link: None,
        refute_reason: None,
        verdict: TriageVerdict::FalsePositive,
        confidence: 0.91,
        rationale: "operator rejected prior occurrence".to_string(),
        cost_usd: 0.0,
        cost_usd_exact: true,
        estimated_cost_usd: None,
    });
    reviewed.triaged_by = Some(TriageAuthor::Human);

    let mut rerun = finding("demo.rerun", 18, "same durable finding seen later");
    rerun.id = Some(2);
    rerun.identity_id = Some(identity_id);
    rerun.static_proof_state = Some(StaticProofState::SourceSinkLinked);

    let index =
        EffectiveReviewStateIndex::from_findings_and_decisions(&[reviewed, rerun.clone()], &[]);
    let decision = index
        .effective_decision_for(&rerun)
        .expect("identity decision");

    assert_eq!(decision.decision_label(), "rejected_false_positive");
    assert_eq!(decision.source_label(), "durable identity");
    assert_eq!(
        effective_review_decision_conflict_label(&rerun, Some(&decision)).as_deref(),
        Some("reappeared_after_rejection")
    );
    assert!(!effective_review_decision_complete(&rerun, Some(&decision)));
}

#[test]
fn carried_rejected_decision_does_not_conflict_with_rejected_scanner_signal() {
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let mut reviewed = finding("demo.reviewed", 12, "reviewed row");
    reviewed.id = Some(1);
    reviewed.identity_id = Some(identity_id.clone());
    reviewed.triage = Some(TriageOutcome {
        first_link: None,
        refute_reason: None,
        verdict: TriageVerdict::FalsePositive,
        confidence: 0.91,
        rationale: "operator rejected prior occurrence".to_string(),
        cost_usd: 0.0,
        cost_usd_exact: true,
        estimated_cost_usd: None,
    });

    let mut rerun = finding("demo.rerun", 18, "same durable finding rejected again");
    rerun.id = Some(2);
    rerun.identity_id = Some(identity_id);
    rerun.static_proof_state = Some(StaticProofState::StaticallyRejected);

    let index =
        EffectiveReviewStateIndex::from_findings_and_decisions(&[reviewed, rerun.clone()], &[]);
    let decision = index
        .effective_decision_for(&rerun)
        .expect("identity decision");

    assert_eq!(
        effective_review_decision_conflict_label(&rerun, Some(&decision)),
        None
    );
    assert!(effective_review_decision_complete(&rerun, Some(&decision)));
}

#[test]
fn non_triage_review_decision_has_no_legacy_triage_verdict() {
    let finding = finding("demo.suppressed", 22, "reviewed under policy");
    let decision = EffectiveReviewDecision::carried_from_identity(ReviewDecision {
        verdict: ReviewDecisionVerdict::Suppressed,
        author: TriageAuthor::Human,
        confidence: 1.0,
        rationale: "suppressed by approved review policy".to_string(),
        dismiss_reason: None,
        actor: None,
    });

    assert_eq!(decision.decision_label(), "suppressed");
    assert!(decision.complete());
    assert_eq!(decision.triage_verdict_label(), None);
    assert_eq!(
        decision.export_review_context().is_terminal(),
        true,
        "suppressed is a terminal review decision"
    );
    assert!(finding.triage.is_none());
}

#[test]
fn decision_history_is_newest_first_and_never_crosses_durable_identities() {
    let mut selected = finding("demo.selected", 10, "selected");
    selected.id = Some(7);
    selected.identity_id = Some("fi_selected".to_string());
    let records = vec![
        decision_record(1, 7, "fi_selected", "older", "2026-07-01T00:00:00Z"),
        decision_record(2, 7, "fi_other", "wrong identity", "2026-07-03T00:00:00Z"),
        decision_record(3, 8, "fi_selected", "newer", "2026-07-02T00:00:00Z"),
    ];

    let history = review_decision_history_for(&selected, &records);

    assert_eq!(history.len(), 2);
    assert_eq!(history[0].decision.rationale, "newer");
    assert_eq!(history[1].decision.rationale, "older");
}

fn decision_record(
    id: i64,
    finding_id: i64,
    identity_id: &str,
    rationale: &str,
    created_at: &str,
) -> ReviewDecisionRecord {
    ReviewDecisionRecord {
        id,
        finding_id,
        identity_id: Some(identity_id.to_string()),
        decision: ReviewDecision {
            verdict: ReviewDecisionVerdict::RejectedFalsePositive,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: rationale.to_string(),
            dismiss_reason: None,
            actor: Some("operator".to_string()),
        },
        triage_verdict: Some(TriageVerdict::FalsePositive),
        created_at: created_at.to_string(),
        provenance: None,
    }
}

fn finding(rule: &str, line: u32, message: &str) -> Finding {
    Finding::new_tool(
        "semgrep",
        rule,
        "src/lib.rs",
        line,
        None,
        Severity::High,
        message,
    )
}

#[test]
fn repeated_observations_do_not_claim_corroborated_proof() {
    let mut candidate = finding("repeat", 12, "unverified candidate");
    candidate.corroboration_count = 2;
    assert_eq!(evidence_state_label(&candidate), "multiple observations");
    assert_eq!(lifecycle_status_label(&candidate), "candidate");
    assert!(candidate.static_proof_state.is_none());
}
