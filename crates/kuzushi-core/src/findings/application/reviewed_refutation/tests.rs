use super::*;
use crate::findings::{ReviewDecision, ReviewDecisionProvenance, TriageAuthor};

const NOW: u64 = 2_000_000_000;
const HALF_LIFE_SECONDS: u64 = 180 * 86_400;

fn key(rule: &str) -> RefutationCohortKey {
    RefutationCohortKey {
        tool: "semgrep".to_string(),
        rule_id: rule.to_string(),
        rule_version: None,
        tool_version: None,
        rule_set_hash: None,
        config_hash: None,
        language: None,
    }
}

fn fact(id: i64, rule: &str) -> RefutationCohortFact {
    RefutationCohortFact {
        finding_id: id,
        identity_id: None,
        key: key(rule),
    }
}

fn decision(
    id: i64,
    finding_id: i64,
    author: TriageAuthor,
    verdict: ReviewDecisionVerdict,
    created_at: u64,
) -> ReviewDecisionRecord {
    ReviewDecisionRecord {
        id,
        finding_id,
        identity_id: None,
        decision: ReviewDecision {
            verdict,
            author,
            confidence: 1.0,
            rationale: "reviewed".to_string(),
            dismiss_reason: None,
            actor: None,
        },
        triage_verdict: None,
        created_at: created_at.to_string(),
        provenance: Some(ReviewDecisionProvenance {
            event_seq: id as u64,
            event_hash: format!("event-{id}"),
            read_watermark: None,
        }),
    }
}

fn population(
    report: &ReviewedRefutationReport,
    population: RefutationPopulation,
) -> &RefutationPopulationStats {
    report.cohorts[0]
        .populations
        .iter()
        .find(|stats| stats.population == population)
        .unwrap()
}

#[test]
fn report_keeps_reviewed_and_emitted_denominators_visible() {
    let facts = (1..=4).map(|id| fact(id, "CWE-89")).collect::<Vec<_>>();
    let decisions = vec![
        decision(
            1,
            1,
            TriageAuthor::Human,
            ReviewDecisionVerdict::RejectedFalsePositive,
            NOW,
        ),
        decision(
            2,
            2,
            TriageAuthor::Human,
            ReviewDecisionVerdict::Confirmed,
            NOW,
        ),
        decision(
            3,
            3,
            TriageAuthor::Auto,
            ReviewDecisionVerdict::RejectedFalsePositive,
            NOW,
        ),
    ];

    let report = derive_reviewed_refutation_report(&facts, &decisions, NOW);
    let human = population(&report, RefutationPopulation::Human);
    let automatic = population(&report, RefutationPopulation::Automatic);

    assert_eq!((human.refuted, human.reviewed, human.emitted), (1, 2, 4));
    assert_eq!((automatic.refuted, automatic.reviewed), (1, 1));
    assert_eq!(human.observed_refutation_rate, Some(0.5));
    assert_eq!(human.shrunken_refutation_rate, 0.5);
    assert!(human.credible_interval_90[0] < 0.5);
    assert!(human.credible_interval_90[1] > 0.5);
}

#[test]
fn latest_decision_wins_within_each_population_without_crossing_authors() {
    let facts = vec![fact(1, "CWE-22")];
    let decisions = vec![
        decision(
            1,
            1,
            TriageAuthor::Human,
            ReviewDecisionVerdict::RejectedFalsePositive,
            NOW,
        ),
        decision(
            2,
            1,
            TriageAuthor::Human,
            ReviewDecisionVerdict::Confirmed,
            NOW,
        ),
        decision(
            3,
            1,
            TriageAuthor::Auto,
            ReviewDecisionVerdict::RejectedFalsePositive,
            NOW,
        ),
    ];

    let report = derive_reviewed_refutation_report(&facts, &decisions, NOW);

    assert_eq!(population(&report, RefutationPopulation::Human).refuted, 0);
    assert_eq!(
        population(&report, RefutationPopulation::Automatic).refuted,
        1
    );
}

#[test]
fn posterior_uses_beta_prior_and_half_life_decay_but_raw_counts_do_not_decay() {
    let facts = vec![fact(1, "CWE-78"), fact(2, "CWE-78")];
    let decisions = vec![
        decision(
            1,
            1,
            TriageAuthor::Human,
            ReviewDecisionVerdict::RejectedFalsePositive,
            NOW - HALF_LIFE_SECONDS,
        ),
        decision(
            2,
            2,
            TriageAuthor::Human,
            ReviewDecisionVerdict::Confirmed,
            NOW,
        ),
    ];

    let report = derive_reviewed_refutation_report(&facts, &decisions, NOW);
    let human = population(&report, RefutationPopulation::Human);

    assert_eq!((human.refuted, human.reviewed), (1, 2));
    assert!((human.weighted_refuted - 0.5).abs() < 1.0e-10);
    assert!((human.weighted_reviewed - 1.5).abs() < 1.0e-10);
    assert!((human.posterior_alpha - 1.5).abs() < 1.0e-10);
    assert!((human.posterior_beta - 2.0).abs() < 1.0e-10);
}

#[test]
fn undated_legacy_decisions_are_disclosed_and_not_promoted_to_current_evidence() {
    let mut legacy = decision(
        1,
        1,
        TriageAuthor::Human,
        ReviewDecisionVerdict::RejectedFalsePositive,
        NOW,
    );
    legacy.created_at = "legacy".to_string();

    let report = derive_reviewed_refutation_report(&[fact(1, "CWE-79")], &[legacy], NOW);
    let human = population(&report, RefutationPopulation::Human);

    assert_eq!(
        (human.refuted, human.reviewed, human.undated_reviewed),
        (1, 1, 1)
    );
    assert_eq!(human.weighted_reviewed, 0.0);
    assert_eq!(human.shrunken_refutation_rate, 0.5);
}

#[test]
fn rfc3339_decisions_participate_in_decay() {
    let as_of = 1_775_001_600; // 2026-04-01T00:00:00Z
    let mut record = decision(
        1,
        1,
        TriageAuthor::Human,
        ReviewDecisionVerdict::RejectedFalsePositive,
        as_of,
    );
    record.created_at = "2026-04-01T00:00:00Z".to_string();

    let report = derive_reviewed_refutation_report(&[fact(1, "CWE-79")], &[record], as_of);
    let human = population(&report, RefutationPopulation::Human);

    assert_eq!(human.undated_reviewed, 0);
    assert!((human.weighted_reviewed - 1.0).abs() < 1.0e-10);
    assert!((human.weighted_refuted - 1.0).abs() < 1.0e-10);
}

#[test]
fn report_never_changes_or_removes_input_facts_or_decisions() {
    let facts = vec![fact(1, "CWE-89")];
    let decisions = vec![decision(
        1,
        1,
        TriageAuthor::Auto,
        ReviewDecisionVerdict::RejectedFalsePositive,
        NOW,
    )];
    let unchanged_facts = facts.clone();
    let unchanged_decisions = decisions.clone();

    let report = derive_reviewed_refutation_report(&facts, &decisions, NOW);

    assert!(report.report_only);
    assert_eq!(facts, unchanged_facts);
    assert_eq!(decisions, unchanged_decisions);
}

#[test]
fn identity_link_never_reassigns_a_historical_decision_to_another_generation() {
    let mut current = fact(2, "CWE-89");
    current.identity_id = Some("fi-shared".to_string());
    let mut historical = decision(
        1,
        1,
        TriageAuthor::Human,
        ReviewDecisionVerdict::RejectedFalsePositive,
        NOW,
    );
    historical.identity_id = Some("fi-shared".to_string());

    let report = derive_reviewed_refutation_report(&[current], &[historical], NOW);
    let human = population(&report, RefutationPopulation::Human);

    assert_eq!((human.refuted, human.reviewed, human.emitted), (0, 0, 1));
    assert_eq!(report.unmatched_decisions, 1);
}
