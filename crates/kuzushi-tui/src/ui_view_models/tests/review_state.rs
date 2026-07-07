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
        verdict: TriageVerdict::ByDesign,
        confidence: 0.71,
        rationale: "accepted by owner".to_string(),
        cost_usd: 0.0,
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
    assert_eq!(evidence_state_label(&finding), "corroborated");
}

#[test]
fn effective_review_index_uses_loaded_durable_identity_decision() {
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let mut reviewed = finding("demo.reviewed", 12, "reviewed row");
    reviewed.id = Some(1);
    reviewed.created_at = "2026-07-01T00:00:00Z".to_string();
    reviewed.identity_id = Some(identity_id.clone());
    reviewed.triage = Some(TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        confidence: 0.91,
        rationale: "operator confirmed".to_string(),
        cost_usd: 0.0,
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
fn carried_rejected_decision_conflicts_with_new_scanner_signal() {
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let mut reviewed = finding("demo.reviewed", 12, "reviewed row");
    reviewed.id = Some(1);
    reviewed.identity_id = Some(identity_id.clone());
    reviewed.triage = Some(TriageOutcome {
        verdict: TriageVerdict::FalsePositive,
        confidence: 0.91,
        rationale: "operator rejected prior occurrence".to_string(),
        cost_usd: 0.0,
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
        verdict: TriageVerdict::FalsePositive,
        confidence: 0.91,
        rationale: "operator rejected prior occurrence".to_string(),
        cost_usd: 0.0,
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
    let decision = EffectiveReviewDecision {
        decision: ReviewDecision {
            verdict: ReviewDecisionVerdict::Suppressed,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: "suppressed by approved review policy".to_string(),
            dismiss_reason: None,
            actor: None,
        },
        source: EffectiveReviewDecisionSource::DurableIdentity,
    };

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
