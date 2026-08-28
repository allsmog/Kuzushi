use super::*;
use crate::findings::{
    derive_reviewed_refutation_report, RefutationCohortFact, RefutationCohortKey,
    RefutationPopulation, ReviewedRefutationPrior, ReviewedRefutationReport,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
struct CohortMetadata {
    tool_version: Option<String>,
    rule_set_hash: Option<String>,
    config_hash: Option<String>,
    language: Option<String>,
}

impl FindingStore {
    /// Derives a read-only reviewed-refutation report from current emitted
    /// findings plus their immutable decision history.
    pub fn reviewed_refutation_report(&self, as_of_unix: u64) -> Result<ReviewedRefutationReport> {
        let findings = self.list_emitted_finding_generations()?;
        let facts = self.refutation_cohort_facts(&findings)?;
        let decisions = self.list_review_decisions_for_findings(&findings)?;
        Ok(derive_reviewed_refutation_report(
            &facts, &decisions, as_of_unix,
        ))
    }

    /// Human-reviewed priors for the requested current findings. These values
    /// are advisory inputs only; callers can order or prompt with them but
    /// must not use them to remove findings.
    pub(crate) fn reviewed_refutation_priors_for(
        &self,
        findings: &[Finding],
        as_of_unix: u64,
    ) -> Result<BTreeMap<String, ReviewedRefutationPrior>> {
        let emitted = self.list_emitted_finding_generations()?;
        let facts = self.refutation_cohort_facts(&emitted)?;
        let decisions = self.list_review_decisions_for_findings(&emitted)?;
        let report = derive_reviewed_refutation_report(&facts, &decisions, as_of_unix);
        let keys_by_id = facts
            .iter()
            .map(|fact| (fact.finding_id, &fact.key))
            .collect::<BTreeMap<_, _>>();
        Ok(findings
            .iter()
            .filter_map(|finding| prior_for_finding(finding, &keys_by_id, &report))
            .collect())
    }

    fn refutation_cohort_facts(&self, findings: &[Finding]) -> Result<Vec<RefutationCohortFact>> {
        let metadata = self.refutation_cohort_metadata(findings)?;
        Ok(findings
            .iter()
            .filter_map(|finding| cohort_fact(finding, &metadata))
            .collect())
    }

    fn refutation_cohort_metadata(
        &self,
        findings: &[Finding],
    ) -> Result<BTreeMap<i64, CohortMetadata>> {
        let ids = finding_ids_json(findings)?;
        if ids == "[]" {
            return Ok(BTreeMap::new());
        }
        let mut statement = self.conn.prepare(COHORT_METADATA_SQL)?;
        let rows = statement.query_map(params![ids], cohort_metadata_from_row)?;
        rows.collect::<rusqlite::Result<BTreeMap<_, _>>>()
            .context("Could not load reviewed-refutation cohort metadata")
    }
}

const COHORT_METADATA_SQL: &str = r#"
with requested as (
    select cast(value as integer) as finding_id from json_each(?1)
), ranked as (
    select requested.finding_id, observations.tool_version,
           observations.rule_set_hash, snapshots.config_hash, files.language,
           row_number() over (
               partition by requested.finding_id order by observations.created_seq desc
           ) as observation_rank
      from requested
      join finding_observations as observations
        on cast(json_extract(observations.finding_json, '$.id') as integer) = requested.finding_id
      left join target_snapshots as snapshots
        on snapshots.snapshot_hash = observations.snapshot_hash
      left join indexed_files as files
        on files.snapshot_hash = observations.snapshot_hash
       and files.path = observations.display_path
)
select finding_id, tool_version, rule_set_hash, config_hash, language
  from ranked
 where observation_rank = 1
"#;

fn finding_ids_json(findings: &[Finding]) -> Result<String> {
    let ids = findings
        .iter()
        .filter_map(|finding| finding.id)
        .collect::<Vec<_>>();
    serde_json::to_string(&ids).context("Could not serialize refutation cohort finding ids")
}

fn cohort_metadata_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, CohortMetadata)> {
    Ok((
        row.get(0)?,
        CohortMetadata {
            tool_version: row.get(1)?,
            rule_set_hash: row.get(2)?,
            config_hash: row.get(3)?,
            language: row.get(4)?,
        },
    ))
}

fn cohort_fact(
    finding: &Finding,
    metadata: &BTreeMap<i64, CohortMetadata>,
) -> Option<RefutationCohortFact> {
    let finding_id = finding.id?;
    let metadata = metadata.get(&finding_id).cloned().unwrap_or_default();
    Some(RefutationCohortFact {
        finding_id,
        identity_id: finding.identity_id.clone(),
        key: RefutationCohortKey {
            tool: finding.tool.clone(),
            rule_id: finding.rule_id.clone(),
            rule_version: finding.rule_version.clone(),
            tool_version: metadata.tool_version,
            rule_set_hash: metadata.rule_set_hash,
            config_hash: metadata.config_hash,
            language: metadata.language,
        },
    })
}

fn prior_for_finding(
    finding: &Finding,
    keys_by_id: &BTreeMap<i64, &RefutationCohortKey>,
    report: &ReviewedRefutationReport,
) -> Option<(String, ReviewedRefutationPrior)> {
    let key = (*keys_by_id.get(&finding.id?)?).clone();
    let cohort = report.cohorts.iter().find(|cohort| cohort.key == key)?;
    let stats = cohort
        .populations
        .iter()
        .find(|stats| stats.population == RefutationPopulation::Human && stats.reviewed > 0)?;
    Some((
        finding.fingerprint.clone(),
        ReviewedRefutationPrior {
            key,
            emitted: stats.emitted,
            reviewed: stats.reviewed,
            refuted: stats.refuted,
            shrunken_refutation_rate: stats.prior_context_rate(),
            credible_interval_90: stats.credible_interval_90,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{
        Finding, FindingIdentityBasis, RefutationPopulation, Severity, TriageAuthor, TriageOutcome,
        TriageVerdict, ReviewedRefutationCohort,
    };

    #[test]
    fn store_report_keeps_persisted_population_and_emission_denominators() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("scan-a", Path::new("/repo"), "completed")
            .unwrap();
        let first = store
            .insert_finding("scan-a", &finding("semgrep", "CWE-89", 10))
            .unwrap();
        store
            .insert_finding("scan-a", &finding("codeql", "CWE-78", 20))
            .unwrap();
        store
            .record_triage_with_author(
                first,
                &TriageOutcome {
                    verdict: TriageVerdict::FalsePositive,
                    ..Default::default()
                },
                TriageAuthor::Human,
            )
            .unwrap();

        let report = store.reviewed_refutation_report(u64::MAX).unwrap();
        let human = report
            .populations
            .iter()
            .find(|stats| stats.population == RefutationPopulation::Human)
            .unwrap();

        assert_eq!((human.refuted, human.reviewed, human.emitted), (1, 1, 2));
        assert_eq!(report.cohorts.len(), 2);
    }

    #[test]
    fn persisted_rule_version_scopes_human_advisory_prior() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("scan-a", Path::new("/repo"), "completed")
            .unwrap();
        let historical = store
            .insert_finding(
                "scan-a",
                &finding("semgrep", "CWE-89", 10)
                    .with_rule_version("1")
                    .with_symbol_locator("crate::db::old_sink"),
            )
            .unwrap();
        let current = store
            .insert_finding(
                "scan-a",
                &Finding::new_tool(
                    "semgrep",
                    "CWE-89",
                    "src/current.rs",
                    20,
                    Some(20),
                    Severity::High,
                    "current candidate",
                )
                .with_rule_version("1")
                .with_symbol_locator("crate::db::new_sink"),
            )
            .unwrap();
        let changed_version = store
            .insert_finding(
                "scan-a",
                &Finding::new_tool(
                    "semgrep",
                    "CWE-89",
                    "src/future.rs",
                    30,
                    Some(30),
                    Severity::High,
                    "future candidate",
                )
                .with_rule_version("2"),
            )
            .unwrap();
        store
            .record_triage_with_author(
                historical,
                &TriageOutcome {
                    verdict: TriageVerdict::FalsePositive,
                    ..Default::default()
                },
                TriageAuthor::Human,
            )
            .unwrap();
        store
            .record_triage_with_author(
                changed_version,
                &TriageOutcome {
                    verdict: TriageVerdict::FalsePositive,
                    ..Default::default()
                },
                TriageAuthor::Auto,
            )
            .unwrap();
        let mut selected = store
            .list_all_findings()
            .unwrap()
            .into_iter()
            .filter(|finding| [current, changed_version].contains(&finding.id.unwrap_or_default()))
            .collect::<Vec<_>>();
        selected.sort_by_key(|finding| finding.id);

        let priors = store
            .reviewed_refutation_priors_for(&selected, current_unix())
            .unwrap();

        assert_eq!(selected.len(), 2);
        let current_prior = priors.get(&selected[0].fingerprint).unwrap();
        assert_eq!((current_prior.refuted, current_prior.reviewed), (1, 1));
        assert_eq!(current_prior.emitted, 2);
        assert!(!priors.contains_key(&selected[1].fingerprint));
        assert_eq!(selected[0].rule_version.as_deref(), Some("1"));
        assert_eq!(
            selected[0].symbol_locator.as_deref(),
            Some("crate::db::new_sink")
        );
        assert_eq!(
            selected[0].effective_identity_basis(),
            FindingIdentityBasis::SourceLocator
        );
    }

    #[test]
    fn historical_decision_stays_with_its_emitted_rule_version() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("scan-old", Path::new("/repo"), "completed")
            .unwrap();
        let old_id = store
            .insert_finding(
                "scan-old",
                &finding("semgrep", "CWE-89", 10).with_rule_version("1"),
            )
            .unwrap();
        store
            .record_triage_with_author(
                old_id,
                &TriageOutcome {
                    verdict: TriageVerdict::FalsePositive,
                    ..Default::default()
                },
                TriageAuthor::Human,
            )
            .unwrap();

        store
            .record_run_started("scan-current", Path::new("/repo"), "completed")
            .unwrap();
        store
            .insert_finding(
                "scan-current",
                &finding("semgrep", "CWE-89", 10).with_rule_version("2"),
            )
            .unwrap();

        let report = store.reviewed_refutation_report(current_unix()).unwrap();
        let old = report
            .cohorts
            .iter()
            .find(|cohort| cohort.key.rule_version.as_deref() == Some("1"))
            .unwrap();
        let current = report
            .cohorts
            .iter()
            .find(|cohort| cohort.key.rule_version.as_deref() == Some("2"))
            .unwrap();
        let old_human = human_population(old);
        let current_human = human_population(current);
        assert_eq!((old_human.refuted, old_human.reviewed), (1, 1));
        assert_eq!((current_human.refuted, current_human.reviewed), (0, 0));
        assert_eq!(report.emitted, 2);
    }

    fn human_population(
        cohort: &ReviewedRefutationCohort,
    ) -> &crate::findings::RefutationPopulationStats {
        cohort
            .populations
            .iter()
            .find(|stats| stats.population == RefutationPopulation::Human)
            .unwrap()
    }

    fn current_unix() -> u64 {
        u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).unwrap()
    }

    fn finding(tool: &str, rule: &str, line: u32) -> Finding {
        Finding::new_tool(
            tool,
            rule,
            "src/app.rs",
            line,
            Some(line),
            Severity::High,
            "candidate",
        )
    }
}
