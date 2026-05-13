use super::*;

impl FindingStore {
    pub fn get_finding_by_fingerprint(&self, fingerprint: &str) -> Result<Option<Finding>> {
        let mut finding = self
            .conn
            .query_row(
                r#"
                select
                  f.id, f.scan_id, f.fingerprint, f.rule_id, f.title, f.severity,
                  f.file_path, f.start_line, f.end_line, f.message, f.tool, f.actor_fingerprint,
                  f.static_proof_state, f.created_at,
                  t.verdict, t.confidence, t.rationale, t.cost_usd,
                  f.vuln_source, f.dedup_key
                from findings f
                left join triage t on t.finding_id = f.id
                where f.fingerprint = ?1
                order by f.id desc
                limit 1
                "#,
                params![fingerprint],
                row_to_finding,
            )
            .optional()
            .context("Could not load finding")?;

        self.attach_evidence_to_finding(finding.as_mut())?;
        self.attach_latest_verification(finding.as_mut())?;
        Ok(finding)
    }

    pub fn get_finding_by_reference(&self, reference: &str) -> Result<Option<Finding>> {
        let reference = reference.trim();
        if reference.is_empty() {
            anyhow::bail!("finding reference must not be empty");
        }

        if let Some(finding) = self.get_finding_by_fingerprint(reference)? {
            return Ok(Some(finding));
        }

        let like_pattern = format!("{reference}%");
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
            where f.fingerprint like ?1
            order by f.id desc
            limit 2
            "#,
        )?;

        let rows = stmt.query_map(params![like_pattern], row_to_finding)?;
        let matches = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not resolve finding reference")?;

        match matches.len() {
            0 => Ok(None),
            1 => {
                let mut finding = matches.into_iter().next();
                self.attach_evidence_to_finding(finding.as_mut())?;
                self.attach_latest_verification(finding.as_mut())?;
                Ok(finding)
            }
            _ => anyhow::bail!("finding reference {reference:?} is ambiguous"),
        }
    }

    pub(crate) fn attach_latest_verification(&self, finding: Option<&mut Finding>) -> Result<()> {
        if let Some(finding) = finding {
            if let Some(id) = finding.id {
                finding.verification = self.get_latest_verification(id)?;
            }
        }
        Ok(())
    }
}
