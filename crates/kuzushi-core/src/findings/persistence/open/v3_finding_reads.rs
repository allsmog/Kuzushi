use super::*;
use rusqlite::types::Type;
use std::collections::BTreeMap;

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
        let mut stmt = self.conn.prepare(
            r#"
            select finding_json
              from finding_observations
             where finding_json is not null
             order by created_seq asc
            "#,
        )?;
        let rows = stmt.query_map([], row_to_v3_finding)?;
        let mut findings = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list v3 findings")?;
        findings = dedupe_latest_by_projected_id(findings);
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
        let like_pattern = format!("{reference}%");
        let mut stmt = self.conn.prepare(
            r#"
            select finding_json
              from finding_observations
             where finding_json is not null
               and json_extract(finding_json, '$.fingerprint') like ?1
             order by created_seq desc
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
        let stable_fps = findings
            .iter()
            .map(finding_stable_fp)
            .collect::<Vec<_>>();
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

fn dedupe_latest_by_projected_id(findings: Vec<Finding>) -> Vec<Finding> {
    let mut order = Vec::<String>::new();
    let mut by_key = BTreeMap::<String, Finding>::new();
    for finding in findings {
        let key = projected_finding_key(&finding);
        if !by_key.contains_key(&key) {
            order.push(key.clone());
        }
        by_key.insert(key, finding);
    }
    order.into_iter()
        .filter_map(|key| by_key.remove(&key))
        .collect()
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
        .then_with(|| right.id.unwrap_or_default().cmp(&left.id.unwrap_or_default()))
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
