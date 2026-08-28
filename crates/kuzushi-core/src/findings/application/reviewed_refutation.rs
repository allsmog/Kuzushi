//! Transparent reviewed-refutation statistics.
//!
//! The report keeps emitted and reviewed denominators visible, separates
//! author populations, and applies a Beta(1,1) prior only to the advisory
//! posterior. It does not suppress, rekey, or otherwise decide a finding.

use super::{ReviewDecisionRecord, ReviewDecisionVerdict};
use std::collections::{BTreeMap, BTreeSet};

mod beta;
mod types;

pub use types::{
    RefutationCohortFact, RefutationCohortKey, RefutationPopulation, RefutationPopulationStats,
    ReviewedRefutationCohort, ReviewedRefutationPrior, ReviewedRefutationReport,
};

const DECAY_HALF_LIFE_DAYS: f64 = 180.0;
const SECONDS_PER_DAY: f64 = 86_400.0;

/// Builds advisory cohort statistics from persisted facts and decisions.
/// Raw counts remain unweighted and visible; only posterior evidence decays.
pub fn derive_reviewed_refutation_report(
    facts: &[RefutationCohortFact],
    decisions: &[ReviewDecisionRecord],
    as_of_unix: u64,
) -> ReviewedRefutationReport {
    let facts_by_cohort = facts_by_cohort(facts);
    let latest = latest_decisions_by_population(decisions);
    let known_ids = facts
        .iter()
        .map(|fact| fact.finding_id)
        .collect::<BTreeSet<_>>();
    let all_ids = known_ids.iter().copied().collect::<BTreeSet<_>>();
    ReviewedRefutationReport {
        report_only: true,
        prior: "Beta(1,1)".to_string(),
        interval: "90% credible interval".to_string(),
        decay_half_life_days: DECAY_HALF_LIFE_DAYS as u32,
        as_of_unix,
        emitted: known_ids.len(),
        unmatched_decisions: unmatched_decision_count(facts, decisions, &known_ids),
        populations: report_populations(&all_ids, &latest, as_of_unix),
        cohorts: facts_by_cohort
            .into_iter()
            .map(|(key, ids)| cohort_report(key, ids, &latest, as_of_unix))
            .collect(),
        limitations: refutation_schema_limitations(facts),
    }
}

fn report_populations(
    ids: &BTreeSet<i64>,
    decisions: &LatestDecisionMap,
    as_of_unix: u64,
) -> Vec<RefutationPopulationStats> {
    [
        RefutationPopulation::Human,
        RefutationPopulation::Automatic,
        RefutationPopulation::Imported,
    ]
    .into_iter()
    .map(|population| population_stats(population, ids, decisions, as_of_unix))
    .collect()
}

fn facts_by_cohort(facts: &[RefutationCohortFact]) -> BTreeMap<RefutationCohortKey, BTreeSet<i64>> {
    let mut cohorts = BTreeMap::<RefutationCohortKey, BTreeSet<i64>>::new();
    for fact in facts {
        cohorts
            .entry(fact.key.clone())
            .or_default()
            .insert(fact.finding_id);
    }
    cohorts
}

type LatestDecisionMap = BTreeMap<(i64, RefutationPopulation), ReviewDecisionRecord>;

fn latest_decisions_by_population(decisions: &[ReviewDecisionRecord]) -> LatestDecisionMap {
    let mut latest = LatestDecisionMap::new();
    for decision in decisions {
        let population = RefutationPopulation::from_author(decision.decision.author);
        let key = (decision.finding_id, population);
        if latest
            .get(&key)
            .is_none_or(|current| current.id < decision.id)
        {
            latest.insert(key, decision.clone());
        }
    }
    latest
}

fn cohort_report(
    key: RefutationCohortKey,
    ids: BTreeSet<i64>,
    decisions: &LatestDecisionMap,
    as_of_unix: u64,
) -> ReviewedRefutationCohort {
    let populations = report_populations(&ids, decisions, as_of_unix);
    ReviewedRefutationCohort { key, populations }
}

fn population_stats(
    population: RefutationPopulation,
    ids: &BTreeSet<i64>,
    decisions: &LatestDecisionMap,
    as_of_unix: u64,
) -> RefutationPopulationStats {
    let records = ids
        .iter()
        .filter_map(|id| decisions.get(&(*id, population)))
        .collect::<Vec<_>>();
    let reviewed = records.len();
    let refuted = records.iter().filter(|record| is_refuted(record)).count();
    let evidence = decayed_evidence(&records, as_of_unix);
    build_population_stats(population, ids.len(), reviewed, refuted, evidence)
}

#[derive(Debug, Clone, Copy)]
struct DecayedEvidence {
    reviewed: f64,
    refuted: f64,
    undated: usize,
}

fn decayed_evidence(records: &[&ReviewDecisionRecord], as_of_unix: u64) -> DecayedEvidence {
    let mut evidence = DecayedEvidence {
        reviewed: 0.0,
        refuted: 0.0,
        undated: 0,
    };
    for record in records {
        let Some(weight) = decision_weight(record, as_of_unix) else {
            evidence.undated += 1;
            continue;
        };
        evidence.reviewed += weight;
        if is_refuted(record) {
            evidence.refuted += weight;
        }
    }
    evidence
}

fn decision_weight(record: &ReviewDecisionRecord, as_of_unix: u64) -> Option<f64> {
    let decided_at = parse_decision_timestamp(&record.created_at)?;
    let age_seconds = as_of_unix.saturating_sub(decided_at) as f64;
    let age_half_lives = age_seconds / (DECAY_HALF_LIFE_DAYS * SECONDS_PER_DAY);
    Some(2.0_f64.powf(-age_half_lives))
}

fn parse_decision_timestamp(value: &str) -> Option<u64> {
    value.parse::<u64>().ok().or_else(|| {
        let parsed =
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                .ok()?;
        u64::try_from(parsed.unix_timestamp()).ok()
    })
}

fn is_refuted(record: &ReviewDecisionRecord) -> bool {
    record.decision.verdict == ReviewDecisionVerdict::RejectedFalsePositive
}

fn build_population_stats(
    population: RefutationPopulation,
    emitted: usize,
    reviewed: usize,
    refuted: usize,
    evidence: DecayedEvidence,
) -> RefutationPopulationStats {
    let alpha = 1.0 + evidence.refuted;
    let beta = 1.0 + (evidence.reviewed - evidence.refuted).max(0.0);
    RefutationPopulationStats {
        population,
        emitted,
        reviewed,
        refuted,
        observed_refutation_rate: observed_rate(refuted, reviewed),
        weighted_reviewed: evidence.reviewed,
        weighted_refuted: evidence.refuted,
        posterior_alpha: alpha,
        posterior_beta: beta,
        shrunken_refutation_rate: alpha / (alpha + beta),
        credible_interval_90: [
            beta::beta_quantile(0.05, alpha, beta),
            beta::beta_quantile(0.95, alpha, beta),
        ],
        undated_reviewed: evidence.undated,
    }
}

fn observed_rate(refuted: usize, reviewed: usize) -> Option<f64> {
    (reviewed > 0).then(|| refuted as f64 / reviewed as f64)
}

fn unmatched_decision_count(
    _facts: &[RefutationCohortFact],
    decisions: &[ReviewDecisionRecord],
    known_ids: &BTreeSet<i64>,
) -> usize {
    decisions
        .iter()
        .filter(|decision| !known_ids.contains(&decision.finding_id))
        .count()
}

fn refutation_schema_limitations(facts: &[RefutationCohortFact]) -> Vec<String> {
    let mut limitations = vec![
        "undated legacy decisions remain in raw denominators but are excluded from decayed posterior evidence"
            .to_string(),
    ];
    append_missing_dimension(
        &mut limitations,
        facts,
        |key| key.rule_version.as_ref(),
        "ruleVersion",
    );
    append_missing_dimension(
        &mut limitations,
        facts,
        |key| key.tool_version.as_ref(),
        "toolVersion",
    );
    append_missing_dimension(
        &mut limitations,
        facts,
        |key| key.rule_set_hash.as_ref(),
        "ruleSetHash",
    );
    append_missing_dimension(
        &mut limitations,
        facts,
        |key| key.config_hash.as_ref(),
        "configHash",
    );
    append_missing_dimension(
        &mut limitations,
        facts,
        |key| key.language.as_ref(),
        "language",
    );
    limitations
}

fn append_missing_dimension<'a>(
    limitations: &mut Vec<String>,
    facts: &'a [RefutationCohortFact],
    value: impl Fn(&'a RefutationCohortKey) -> Option<&'a String>,
    label: &str,
) {
    if facts.iter().any(|fact| value(&fact.key).is_none()) {
        limitations.push(format!(
            "{label} is absent on some emitted findings; missing values stay in an explicit null cohort"
        ));
    }
}

#[cfg(test)]
mod tests;
