use super::*;
use rusqlite::types::Type;
use std::collections::BTreeMap;

const LATEST_FINDING_PROJECTION_SQL: &str = r#"
with observations as (
    select finding_json,
           coalesce(nullif(json_extract(finding_json, '$.identityId'), ''),
                    json_extract(finding_json, '$.fingerprint')) as stable_key,
           created_seq
      from finding_observations
     where finding_json is not null
), ranked_observations as (
    select finding_json, stable_key,
           row_number() over (
               partition by stable_key
               order by created_seq desc
           ) as observation_rank
      from observations
), merged_sources as (
    select observations.stable_key,
           json_group_array(json(source.value)) as sources_json
      from observations
      join json_each(observations.finding_json, '$.sources') as source
     group by observations.stable_key
)
select latest.finding_json,
       coalesce(merged_sources.sources_json, '[]') as sources_json
  from ranked_observations as latest
  left join merged_sources on merged_sources.stable_key = latest.stable_key
 where latest.observation_rank = 1
"#;

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

    pub(crate) fn v3_all_findings(&self) -> Result<Vec<Finding>> {
        let mut stmt = self.conn.prepare(LATEST_FINDING_PROJECTION_SQL)?;
        let rows = stmt.query_map([], row_to_v3_projected_finding)?;
        let mut findings = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list v3 findings")?;
        findings.sort_by(finding_list_order);
        self.hydrate_v3_findings(findings)
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

    fn hydrate_v3_findings(&self, mut findings: Vec<Finding>) -> Result<Vec<Finding>> {
        self.hydrate_v3_findings_in_place(&mut findings)?;
        Ok(findings)
    }

    fn hydrate_v3_findings_in_place(&self, findings: &mut [Finding]) -> Result<()> {
        self.attach_latest_verifications_to_findings(findings)?;
        self.hydrate_suppressed_flag(findings)
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
fn finding_stable_fp(finding: &Finding) -> String {
    finding
        .identity_id
        .clone()
        .unwrap_or_else(|| finding.fingerprint.clone())
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

fn finding_list_order(left: &Finding, right: &Finding) -> std::cmp::Ordering {
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
