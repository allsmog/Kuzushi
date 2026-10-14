use super::*;
use crate::strategy::{StrategyPhase, StrategyPreflight, StrategyResourceRisk};

fn draft(run: Option<&str>) -> StrategyProposal {
    let mut proposal = StrategyProposal::new_at(
        10,
        StrategyPhase::Review,
        "run context:build",
        "Owned metadata context",
    );
    proposal.id = "review-context-build".into();
    proposal.tool = Some("context:build".into());
    proposal.next_input = Some(serde_json::json!({"paths":["owned.rs"]}));
    proposal.source_run_id = run.map(str::to_owned);
    proposal.preflight = StrategyPreflight::ready();
    proposal.resource_risk = StrategyResourceRisk::Low;
    proposal
}

#[test]
fn refresh_preserves_every_reviewed_status_and_complete_prior_record() {
    for status in [
        StrategyProposalStatus::Approved,
        StrategyProposalStatus::Rejected,
        StrategyProposalStatus::Running,
        StrategyProposalStatus::Done,
        StrategyProposalStatus::Failed,
    ] {
        let mut old = draft(Some("old-run"));
        old.status = status;
        old.corrected_strategy = Some("retained operator correction".into());
        old.approved_cost_usd = Some(0.5);
        old.actual_cost_usd = Some(0.2);
        old.findings_count = Some(3);
        old.confirmed_count = Some(1);
        old.result_run_id = Some("historical-result".into());
        old.failure = Some("retained failure evidence".into());
        let mut queue = vec![old.clone()];
        let id = retain_draft(&mut queue, draft(Some("new-run"))).unwrap();
        assert_eq!(queue[0], old);
        assert_ne!(id, old.id);
        assert_eq!(queue[1].status, StrategyProposalStatus::Proposed);
        assert_eq!(queue[1].approved_cost_usd, None);
        assert_eq!(queue[1].result_run_id, None);
        assert_eq!(queue[1].source_run_id.as_deref(), Some("new-run"));
    }
}

#[test]
fn same_run_replay_reuses_only_an_unchanged_unreviewed_draft() {
    let old = draft(Some("one-run"));
    let mut queue = vec![old.clone()];
    let id = retain_draft(&mut queue, draft(Some("one-run"))).unwrap();
    assert_eq!(id, old.id);
    assert_eq!(queue, vec![old]);
}

#[test]
fn same_run_reviewed_record_is_retained_but_never_published_as_a_new_draft() {
    let mut old = draft(Some("one-run"));
    old.status = StrategyProposalStatus::Approved;
    old.approved_cost_usd = Some(0.7);
    let mut queue = vec![old.clone()];
    let id = retain_draft(&mut queue, draft(Some("one-run"))).unwrap();
    assert_ne!(id, old.id);
    assert_eq!(queue[0], old);
    assert_eq!(queue[1].status, StrategyProposalStatus::Proposed);
    assert_eq!(queue[1].approved_cost_usd, None);
}

#[test]
fn changed_input_in_the_same_run_requires_a_separate_unapproved_identity() {
    let mut old = draft(Some("one-run"));
    old.status = StrategyProposalStatus::Approved;
    let mut next = draft(Some("one-run"));
    next.next_input = Some(serde_json::json!({"paths":["other.rs"]}));
    let mut queue = vec![old.clone()];
    let id = retain_draft(&mut queue, next).unwrap();
    assert_ne!(id, old.id);
    assert_eq!(queue[0], old);
    assert_eq!(queue[1].status, StrategyProposalStatus::Proposed);
}

#[test]
fn runs_without_an_identity_never_reuse_prior_review_authority() {
    let mut old = draft(None);
    old.status = StrategyProposalStatus::Approved;
    let mut queue = vec![old.clone()];
    retain_draft(&mut queue, draft(None)).unwrap();
    retain_draft(&mut queue, draft(None)).unwrap();
    assert_eq!(queue[0], old);
    assert_eq!(queue.len(), 3);
    assert_ne!(queue[1].id, queue[2].id);
    assert!(queue[1..]
        .iter()
        .all(|p| p.status == StrategyProposalStatus::Proposed));
}

#[test]
fn fresh_legacy_identity_and_operator_corrections_remain_compatible() {
    let mut next = draft(Some("fresh"));
    next.corrected_strategy = Some("operator scoped context".into());
    let mut queue = Vec::new();
    let id = retain_draft(&mut queue, next.clone()).unwrap();
    assert_eq!(id, "review-context-build");
    assert_eq!(queue, vec![next]);
}

#[test]
fn non_draft_generation_fails_without_mutating_history() {
    let old = draft(Some("old"));
    let mut next = draft(Some("new"));
    next.status = StrategyProposalStatus::Approved;
    let mut queue = vec![old.clone()];
    assert!(retain_draft(&mut queue, next).is_err());
    assert_eq!(queue, vec![old]);
}
