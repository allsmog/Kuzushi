use super::*;

impl FindingStore {
    pub fn list_findings(&self, limit: usize) -> Result<Vec<Finding>> {
        Ok(self
            .list_findings_filtered(&FindingListFilter::with_limit(limit))?
            .findings)
    }

    pub fn list_findings_for_scan_id(&self, scan_id: &str) -> Result<Vec<Finding>> {
        let mut stmt = self.conn.prepare(
            r#"
            select
              f.id, f.scan_id, f.fingerprint, f.rule_id, f.title, f.severity,
              f.file_path, f.start_line, f.end_line, f.message, f.tool, f.actor_fingerprint,
              f.static_proof_state, f.created_at,
              t.verdict, t.confidence, t.rationale, t.cost_usd,
              f.vuln_source, f.dedup_key
            from findings f
            left join triage t on t.finding_id = f.id
            where f.scan_id = ?1
            order by f.id asc
            "#,
        )?;
        let rows = stmt.query_map(params![scan_id], row_to_finding)?;
        let mut findings = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list findings for scan run")?;
        self.attach_evidence_to_findings(&mut findings)?;
        Ok(findings)
    }

    pub fn list_findings_filtered(&self, filter: &FindingListFilter) -> Result<FindingListReport> {
        let mut stmt = self.conn.prepare(
            r#"
            select
              f.id, f.scan_id, f.fingerprint, f.rule_id, f.title, f.severity,
              f.file_path, f.start_line, f.end_line, f.message, f.tool, f.actor_fingerprint,
              f.static_proof_state, f.created_at,
              t.verdict, t.confidence, t.rationale, t.cost_usd,
              f.vuln_source, f.dedup_key
            from findings f
            left join triage t on t.finding_id = f.id
            order by
              case f.severity
                when 'critical' then 0
                when 'high' then 1
                when 'medium' then 2
                when 'low' then 3
                when 'info' then 4
                else 5
              end,
              f.id desc
            "#,
        )?;

        let rows = stmt.query_map([], row_to_finding)?;
        let mut count = 0;
        let mut findings = Vec::new();
        for row in rows {
            let finding = row.context("Could not list findings")?;
            if !filter.matches(&finding) {
                continue;
            }
            count += 1;
            if findings.len() < filter.limit {
                findings.push(finding);
            }
        }

        self.attach_evidence_to_findings(&mut findings)?;
        Ok(FindingListReport { count, findings })
    }
}
