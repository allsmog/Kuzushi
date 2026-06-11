use super::*;

impl FindingStore {
    pub fn insert_finding(&self, scan_id: &str, finding: &Finding) -> Result<i64> {
        // The collision-check → upsert → evidence-replace sequence must be
        // atomic: a crash or concurrent writer between statements could leave
        // a finding without its evidence rows. SQLite transactions are
        // connection-scoped, so the helper statements below participate.
        let tx = self.conn.unchecked_transaction()?;
        let id = self.insert_finding_statements(scan_id, finding)?;
        tx.commit()?;
        Ok(id)
    }

    fn insert_finding_statements(&self, scan_id: &str, finding: &Finding) -> Result<i64> {
        // Cross-channel dedup: when a finding with the same dedup_key but a
        // different fingerprint already exists in this scan, merge instead
        // of inserting a duplicate row. Higher severity wins; tools merge
        // into a comma-list. Skipped silently when the new finding has no
        // dedup_key (legacy callers).
        if let Some(dedup_key) = finding.dedup_key.as_deref() {
            if let Some(existing) = self.find_collision(scan_id, dedup_key, &finding.fingerprint)? {
                return self.merge_finding_collision(existing, finding);
            }
        }

        self.upsert_finding(scan_id, finding)?;
        let id: i64 = self.conn.query_row(
            "select id from findings where scan_id = ?1 and fingerprint = ?2",
            params![scan_id, finding.fingerprint],
            |row| row.get(0),
        )?;
        self.replace_finding_evidence(id, &finding.evidence)?;
        Ok(id)
    }

    fn upsert_finding(&self, scan_id: &str, finding: &Finding) -> Result<()> {
        let references_json = references_json(&finding.references)?;
        self.conn.execute(
            UPSERT_FINDING_SQL,
            params![
                scan_id,
                finding.fingerprint,
                finding.rule_id,
                finding.title,
                finding.severity.as_str(),
                finding.file_path,
                finding.start_line,
                finding.end_line,
                finding.message,
                finding.tool,
                finding.actor_fingerprint,
                finding.static_proof_state.map(StaticProofState::as_str),
                finding.created_at,
                finding.vuln_source.map(|s| s.as_str()),
                finding.dedup_key,
                finding.suppressed,
                finding.snoozed_until,
                finding.remediation,
                references_json,
            ],
        )?;
        Ok(())
    }

    fn merge_finding_collision(&self, existing: Finding, finding: &Finding) -> Result<i64> {
        let merge_id = existing.id.expect("existing finding always has id");
        let merged_tool = merge_tool_list(&existing.tool, &finding.tool);
        let merged_source = merge_vuln_source(existing.vuln_source, finding.vuln_source);
        if finding.severity > existing.severity {
            self.replace_collision_headline(merge_id, finding, &merged_tool, merged_source)?;
            self.replace_finding_evidence(merge_id, &finding.evidence)?;
        } else if existing.tool != merged_tool {
            self.update_collision_tool(merge_id, &merged_tool, merged_source)?;
        }
        Ok(merge_id)
    }

    fn replace_collision_headline(
        &self,
        id: i64,
        finding: &Finding,
        merged_tool: &str,
        merged_source: Option<VulnSource>,
    ) -> Result<()> {
        self.conn.execute(
            r#"update findings set
                 severity = ?, rule_id = ?, title = ?, message = ?,
                 tool = ?, vuln_source = ?, suppressed = ?,
                 snoozed_until = ?, remediation = ?, references_json = ?
               where id = ?"#,
            params![
                finding.severity.as_str(),
                finding.rule_id,
                finding.title,
                finding.message,
                merged_tool,
                merged_source.map(|s| s.as_str()),
                finding.suppressed,
                finding.snoozed_until,
                finding.remediation,
                references_json(&finding.references)?,
                id,
            ],
        )?;
        Ok(())
    }

    fn update_collision_tool(
        &self,
        id: i64,
        merged_tool: &str,
        merged_source: Option<VulnSource>,
    ) -> Result<()> {
        self.conn.execute(
            "update findings set tool = ?, vuln_source = ? where id = ?",
            params![merged_tool, merged_source.map(|s| s.as_str()), id],
        )?;
        Ok(())
    }

    /// Look up an existing finding in the same scan that shares the
    /// dedup_key but differs in fingerprint. Returns the existing
    /// finding's `(id, severity, tool, vuln_source)` enough to drive
    /// merge logic.
    pub(crate) fn find_collision(
        &self,
        scan_id: &str,
        dedup_key: &str,
        new_fingerprint: &str,
    ) -> Result<Option<Finding>> {
        let mut stmt = self.conn.prepare(
            "select id, severity, tool, vuln_source
               from findings
              where scan_id = ?1
                and dedup_key = ?2
                and fingerprint != ?3
              limit 1",
        )?;
        let row: Option<(i64, String, String, Option<String>)> = stmt
            .query_row(params![scan_id, dedup_key, new_fingerprint], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .optional()?;
        Ok(row.map(|(id, sev_str, tool, src_str)| {
            let severity = Severity::try_from(sev_str.as_str()).unwrap_or(Severity::Unknown);
            let vuln_source = src_str.as_deref().and_then(VulnSource::parse);
            Finding {
                id: Some(id),
                scan_id: Some(scan_id.to_string()),
                severity,
                tool,
                vuln_source,
                dedup_key: Some(dedup_key.to_string()),
                ..Finding::default()
            }
        }))
    }
}

fn references_json(references: &[String]) -> Result<Option<String>> {
    if references.is_empty() {
        return Ok(None);
    }
    Ok(Some(serde_json::to_string(references)?))
}

const UPSERT_FINDING_SQL: &str = r#"
insert into findings(
  scan_id, fingerprint, rule_id, title, severity, file_path,
  start_line, end_line, message, tool, actor_fingerprint,
  static_proof_state, created_at, vuln_source, dedup_key,
  suppressed, snoozed_until, remediation, references_json
)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
        ?16, ?17, ?18, ?19)
on conflict(scan_id, fingerprint) do update set
  title = excluded.title,
  severity = excluded.severity,
  message = excluded.message,
  actor_fingerprint = excluded.actor_fingerprint,
  static_proof_state = coalesce(excluded.static_proof_state, findings.static_proof_state),
  vuln_source = coalesce(excluded.vuln_source, findings.vuln_source),
  dedup_key = coalesce(excluded.dedup_key, findings.dedup_key),
  suppressed = excluded.suppressed,
  snoozed_until = excluded.snoozed_until,
  remediation = excluded.remediation,
  references_json = excluded.references_json
"#;
