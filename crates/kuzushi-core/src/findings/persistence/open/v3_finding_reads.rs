use super::*;
use rusqlite::types::Type;
use std::collections::BTreeMap;
mod dedupe_inputs;
mod grounding_candidates;
mod recommendation_paths;

/// The latest observation per stable identity — the ledger's current
/// finding set. Shared by the full projection below and the narrow
/// review-decision-subject projection, so both agree on what "current" means.
///
/// Stable-key policy mirrors the Rust safe fold in
/// `identity_fold_projection.rs`: strong-basis observations key on their
/// identity; a weak (file-fallback) observation joins that identity only when
/// some strong observation of the same identity shares its source signature or
/// dedup key — the cross-run case where a later hunt rediscovers a finding
/// first minted without corroboration — and otherwise keeps its own
/// signature- or dedup-scoped key so distinct fallbacks never collapse.
macro_rules! latest_observation_ranking_cte {
    () => {
        r#"
with observation_rows as (
    select rowid as observation_rowid,
           finding_json,
           created_seq,
           lower(trim(json_extract(finding_json, '$.tool'))) as tool,
           lower(trim(json_extract(finding_json, '$.rule_id'))) as rule_id,
           json_extract(finding_json, '$.fingerprint') as fingerprint,
           nullif(trim(json_extract(finding_json, '$.identityId')), '') as identity_id,
           (json_extract(finding_json, '$.identityBasis') in (
              'exact_producer_fingerprint', 'cross_run_dedup_key', 'source_locator'
            ) or (json_extract(finding_json, '$.identityBasis') is null
                  and json_extract(finding_json, '$.identityMatchTier') = 'dedup_key_cross_run')
           ) as strong_basis,
           nullif(trim(json_extract(finding_json, '$.source_signature')), '') as source_signature,
           nullif(trim(json_extract(finding_json, '$.dedup_key')), '') as dedup_key
      from finding_observations
     where finding_json is not null
), strong_identity_evidence as materialized (
    select distinct identity_id, source_signature, dedup_key
      from observation_rows
     where identity_id is not null and strong_basis
), folded_weak_observations as materialized (
    select distinct weak.observation_rowid
      from observation_rows as weak
      join strong_identity_evidence as strong
        on strong.identity_id = weak.identity_id
       and (strong.source_signature = weak.source_signature
            or strong.dedup_key = weak.dedup_key)
     where weak.identity_id is not null and not weak.strong_basis
), observations as (
    select finding_json,
           case
             when tool = 'chains' or rule_id like 'exploit-chain/%'
               then 'fingerprint:' || fingerprint
             when identity_id is null
               then 'fingerprint:' || fingerprint
             when strong_basis
               then 'identity:' || identity_id
             when observation_rowid in (select observation_rowid from folded_weak_observations)
               then 'identity:' || identity_id
             when source_signature is not null
               then 'identity:' || identity_id || ':source:' || source_signature
             when dedup_key is not null
               then 'identity:' || identity_id || ':dedup:' || dedup_key
             else 'fingerprint:' || fingerprint
           end as stable_key,
           created_seq
      from observation_rows
), ranked_observations as (
    select finding_json, stable_key,
           row_number() over (
               partition by stable_key
               order by created_seq desc
           ) as observation_rank
      from observations
)"#
    };
}

const LATEST_FINDING_PROJECTION_SQL: &str = concat!(
    latest_observation_ranking_cte!(),
    r#", merged_sources as (
    select observations.stable_key,
           json_group_array(json(source.value) order by observations.created_seq asc, source.key asc) as sources_json
      from observations
      join json_each(observations.finding_json, '$.sources') as source
     group by observations.stable_key
)
select latest.finding_json,
       coalesce(merged_sources.sources_json, '[]') as sources_json
  from ranked_observations as latest
  left join merged_sources on merged_sources.stable_key = latest.stable_key
 where latest.observation_rank = 1
"#
);

const LATEST_FINDING_PATHS_SQL: &str = concat!(
    latest_observation_ranking_cte!(),
    "select json_extract(latest.finding_json, '$.file_path')
       from ranked_observations as latest
      where latest.observation_rank = 1
      order by latest.stable_key limit ?1"
);

/// Only the two columns a review-decision lookup needs, straight from the
/// stored JSON: no `Finding` deserialization, no source merge, no hydration.
const LATEST_REVIEW_DECISION_SUBJECTS_SQL: &str = concat!(
    latest_observation_ranking_cte!(),
    r#"
select cast(json_extract(latest.finding_json, '$.id') as integer) as finding_id,
       nullif(trim(json_extract(latest.finding_json, '$.identityId')), '') as identity_id
  from ranked_observations as latest
 where latest.observation_rank = 1
"#
);

impl FindingStore {
    pub(crate) fn v3_findings_for_scan_id(&self, scan_id: &str) -> Result<Vec<Finding>> {
        let mut stmt = self.conn.prepare(
            r#"
            select finding_json
              from finding_observations
             where finding_json is not null
               and run_id = ?1
             order by created_seq asc
            "#,
        )?;
        let rows = stmt.query_map(params![scan_id], row_to_v3_finding)?;
        let findings = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list v3 findings for scan run")?;
        self.hydrate_v3_findings(dedupe_latest_by_projected_id(findings))
    }

    pub(crate) fn v3_observation_count_for_scan_id(&self, scan_id: &str) -> Result<usize> {
        let count = self
            .conn
            .query_row(
                "select count(*) from finding_observations
                  where finding_json is not null and run_id = ?1",
                params![scan_id],
                |row| row.get::<_, i64>(0),
            )
            .context("Could not count v3 observations for scan run")?;
        Ok(usize::try_from(count).unwrap_or(0))
    }

    pub(crate) fn v3_all_findings(&self) -> Result<Vec<Finding>> {
        let mut stmt = self.conn.prepare(LATEST_FINDING_PROJECTION_SQL)?;
        let rows = stmt.query_map([], row_to_v3_projected_finding)?;
        let mut findings = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list v3 findings")?;
        findings.sort_by(finding_list_order);
        self.hydrate_v3_findings(findings)
    }

    /// Review-decision subjects for every current finding, read without
    /// materializing the findings themselves. Yields the same subject set as
    /// mapping `v3_all_findings()` through `ReviewDecisionSubject::from`.
    pub(crate) fn v3_review_decision_subjects(&self) -> Result<Vec<ReviewDecisionSubject>> {
        let mut stmt = self.conn.prepare(LATEST_REVIEW_DECISION_SUBJECTS_SQL)?;
        let rows = stmt.query_map([], |row| {
            Ok(ReviewDecisionSubject {
                finding_id: row.get(0)?,
                identity_id: row.get(1)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list v3 review-decision subjects")
    }

    pub(crate) fn v3_finding_by_fingerprint(&self, fingerprint: &str) -> Result<Option<Finding>> {
        let finding = self
            .conn
            .query_row(
                r#"
                select finding_json
                  from finding_observations
                 where finding_json is not null
                   and json_extract(finding_json, '$.fingerprint') = ?1
                 order by created_seq desc
                 limit 1
                "#,
                params![fingerprint],
                row_to_v3_finding,
            )
            .optional()
            .context("Could not load v3 finding")?;
        self.hydrate_v3_finding(finding)
    }

    pub(crate) fn v3_finding_by_projected_id(&self, finding_id: i64) -> Result<Option<Finding>> {
        let finding = self
            .conn
            .query_row(
                r#"
                select finding_json
                  from finding_observations
                 where finding_json is not null
                   and json_extract(finding_json, '$.id') = ?1
                 order by created_seq desc
                 limit 1
                "#,
                params![finding_id],
                row_to_v3_finding,
            )
            .optional()
            .context("Could not load v3 finding by projected id")?;
        self.hydrate_v3_finding(finding)
    }

    pub(crate) fn v3_reference_prefix_matches(&self, reference: &str) -> Result<Vec<Finding>> {
        let like_pattern = format!("{}%", escape_like_prefix(reference));
        let mut stmt = self.conn.prepare(
            r#"
            with latest_matches as (
                select json_extract(finding_json, '$.fingerprint') as fingerprint,
                       max(created_seq) as created_seq
                  from finding_observations
                 where finding_json is not null
                   and json_extract(finding_json, '$.fingerprint') like ?1 escape '\'
                 group by fingerprint
                 order by created_seq desc
                 limit 2
            )
            select observations.finding_json
              from latest_matches
              join finding_observations as observations
                on observations.created_seq = latest_matches.created_seq
             order by observations.created_seq desc
             limit 2
            "#,
        )?;
        let rows = stmt.query_map(params![like_pattern], row_to_v3_finding)?;
        let findings = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not resolve v3 finding reference")?;
        self.hydrate_v3_findings(findings)
    }

    fn hydrate_v3_finding(&self, finding: Option<Finding>) -> Result<Option<Finding>> {
        let mut findings = finding.into_iter().collect::<Vec<_>>();
        self.hydrate_v3_findings_in_place(&mut findings)?;
        Ok(findings.into_iter().next())
    }

    pub(super) fn hydrate_v3_findings(&self, mut findings: Vec<Finding>) -> Result<Vec<Finding>> {
        self.hydrate_v3_findings_in_place(&mut findings)?;
        Ok(findings)
    }

    fn hydrate_v3_findings_in_place(&self, findings: &mut [Finding]) -> Result<()> {
        self.attach_latest_verifications_to_findings(findings)?;
        self.hydrate_observation_gaps(findings)?;
        self.hydrate_suppressed_flag(findings)
    }

    fn hydrate_observation_gaps(&self, findings: &mut [Finding]) -> Result<()> {
        let stable_fps = findings.iter().map(finding_stable_fp).collect::<Vec<_>>();
        let gaps = self.current_observation_gaps_for(&stable_fps)?;
        for finding in findings {
            // Presence comes from the ledger, never from producer-supplied JSON
            // or a gap retained in an earlier exported observation.
            finding.observation_gap = gaps.get(&finding_stable_fp(finding)).cloned();
        }
        Ok(())
    }

    /// Project `stable_findings.current_status` onto `Finding.suppressed`.
    /// This is what makes the `status:suppressed` / `verdict:suppressed`
    /// filter tokens and the export "suppressed" column functional.
    fn hydrate_suppressed_flag(&self, findings: &mut [Finding]) -> Result<()> {
        let stable_fps = findings.iter().map(finding_stable_fp).collect::<Vec<_>>();
        let statuses = self.current_statuses_for(&stable_fps)?;
        for finding in findings {
            let stable_fp = finding_stable_fp(finding);
            let projected_suppressed =
                statuses.get(&stable_fp).map(String::as_str) == Some("suppressed");
            // Additive: the projection can mark a finding suppressed, but must
            // not clear a value already carried in the stored finding JSON.
            finding.suppressed = finding.suppressed || projected_suppressed;
        }
        Ok(())
    }
}

fn escape_like_prefix(reference: &str) -> String {
    reference
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Stable projection key: identity id when present, else fingerprint.
pub(crate) fn finding_stable_fp(finding: &Finding) -> String {
    crate::findings::finding_observation_identity(finding).to_owned()
}

fn row_to_v3_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<Finding> {
    let raw: String = row.get(0)?;
    serde_json::from_str(&raw)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(0, Type::Text, Box::new(err)))
}

fn row_to_v3_projected_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<Finding> {
    let mut finding = row_to_v3_finding(row)?;
    let raw_sources: String = row.get(1)?;
    let sources = serde_json::from_str::<Vec<FindingSource>>(&raw_sources)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(1, Type::Text, Box::new(err)))?;
    finding.sources = super::finding_sources::merged_finding_sources(&[], &sources);
    if !finding.sources.is_empty() {
        finding.corroboration_count = finding.sources.len() as u32;
    }
    Ok(finding)
}

fn dedupe_latest_by_projected_id(findings: Vec<Finding>) -> Vec<Finding> {
    dedupe_latest_by(findings, projected_finding_key, keep_latest_observation)
}

fn dedupe_latest_by(
    findings: Vec<Finding>,
    key_for: impl Fn(&Finding) -> String,
    merge_with_previous: impl Fn(&Finding, Finding) -> Finding,
) -> Vec<Finding> {
    let mut order = Vec::<String>::new();
    let mut by_key = BTreeMap::<String, Finding>::new();
    for mut finding in findings {
        let key = key_for(&finding);
        if !by_key.contains_key(&key) {
            order.push(key.clone());
        }
        if let Some(previous) = by_key.get(&key) {
            finding = merge_with_previous(previous, finding);
        }
        by_key.insert(key, finding);
    }
    order
        .into_iter()
        .filter_map(|key| by_key.remove(&key))
        .collect()
}

fn keep_latest_observation(_: &Finding, latest: Finding) -> Finding {
    latest
}

fn projected_finding_key(finding: &Finding) -> String {
    if let Some(id) = finding.id {
        return format!("id:{id}");
    }
    format!(
        "scan:{}:fingerprint:{}",
        finding.scan_id.as_deref().unwrap_or_default(),
        finding.fingerprint
    )
}

pub(super) fn finding_list_order(left: &Finding, right: &Finding) -> std::cmp::Ordering {
    severity_rank(left.severity)
        .cmp(&severity_rank(right.severity))
        .then_with(|| {
            right
                .id
                .unwrap_or_default()
                .cmp(&left.id.unwrap_or_default())
        })
        .then_with(|| left.fingerprint.cmp(&right.fingerprint))
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
        Severity::Unknown => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merged_source_history_follows_ledger_order_with_equal_timestamps_and_reversed_run_names() {
        for reverse in [false, true] {
            let store = FindingStore::open_in_memory().unwrap();
            store
                .conn
                .pragma_update(None, "reverse_unordered_selects", reverse)
                .unwrap();
            let mut finding = Finding::new_tool(
                "owned",
                "repeat",
                "note.md",
                1,
                None,
                Severity::Low,
                "Repeated inert observation",
            );
            finding.created_at = "1000".into();
            for run in ["run-z", "run-m", "run-a"] {
                store
                    .record_run_started(run, Path::new("."), "running")
                    .unwrap();
                store.insert_finding(run, &finding).unwrap();
                store.record_run_finished(run, "completed", 1).unwrap();
            }
            let projected = store.list_all_findings().unwrap();
            assert_eq!(projected.len(), 1);
            assert_eq!(projected[0].sources.len(), 1);
            assert_eq!(projected[0].sources[0].first_scan_id, "run-z");
            assert_eq!(projected[0].sources[0].last_scan_id, "run-a");
            assert_eq!(projected[0].sources[0].first_seen_at, "1000");
            assert_eq!(projected[0].sources[0].last_seen_at, "1000");
            for run in ["run-z", "run-m", "run-a"] {
                let raw: String = store
                    .conn
                    .query_row(
                        "select finding_json from finding_observations where run_id=?1",
                        [run],
                        |row| row.get(0),
                    )
                    .unwrap();
                let raw: Finding = serde_json::from_str(&raw).unwrap();
                assert_eq!(raw.sources[0].first_scan_id, run);
                assert_eq!(raw.sources[0].last_scan_id, run);
            }
        }
    }

    /// The per-insert point lookups must be index searches, not full-table
    /// json_extract scans (the measured ~40 ms/row import cost).
    #[test]
    fn projected_id_and_fingerprint_lookups_use_expression_indexes() {
        let store = FindingStore::open_in_memory().unwrap();
        let cases = [
            (
                "explain query plan select finding_json from finding_observations \
                 where finding_json is not null \
                 and json_extract(finding_json, '$.id') = ?1 \
                 order by created_seq desc limit 1",
                "idx_finding_observations_projected_id",
            ),
            (
                "explain query plan select finding_json from finding_observations \
                 where finding_json is not null \
                 and json_extract(finding_json, '$.fingerprint') = ?1 \
                 order by created_seq desc limit 1",
                "idx_finding_observations_json_fingerprint",
            ),
        ];
        for (sql, index) in cases {
            let mut statement = store.conn.prepare(sql).unwrap();
            let details = statement
                .query_map([1i64], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                details.iter().any(|detail| detail.contains(index)),
                "expected {index} in plan, got {details:?}"
            );
        }
    }

    #[test]
    fn global_projection_query_does_not_rescan_history_per_finding() {
        let store = FindingStore::open_in_memory().unwrap();
        let sql = format!("explain query plan {LATEST_FINDING_PROJECTION_SQL}");
        let mut statement = store.conn.prepare(&sql).unwrap();
        let details = statement
            .query_map([], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();

        assert!(details
            .iter()
            .all(|detail| !detail.contains("CORRELATED SCALAR SUBQUERY")));
    }
}
