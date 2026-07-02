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
        // Cross-channel dedup: when a finding with the same dedup_key already
        // exists in this workspace, merge instead of inserting a duplicate
        // row. Same-scan collisions are preferred; cross-run collisions still
        // accumulate source provenance for engagement-level corroboration.
        if let Some(dedup_key) = finding.dedup_key.as_deref() {
            if let Some(existing) = self.find_collision(scan_id, dedup_key, &finding.fingerprint)? {
                return self.merge_finding_collision(existing, scan_id, finding);
            }
        }

        self.upsert_finding(scan_id, finding)?;
        let id: i64 = self.conn.query_row(
            "select id from findings where scan_id = ?1 and fingerprint = ?2",
            params![scan_id, finding.fingerprint],
            |row| row.get(0),
        )?;
        self.replace_finding_evidence(id, &finding.evidence)?;
        self.record_finding_source(id, scan_id, finding)?;
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
                finding.source_signature,
                finding.corroboration_count.max(1),
                finding.suppressed,
                finding.snoozed_until,
                finding.remediation,
                references_json,
            ],
        )?;
        Ok(())
    }

    fn merge_finding_collision(
        &self,
        existing: Finding,
        scan_id: &str,
        finding: &Finding,
    ) -> Result<i64> {
        let merge_id = existing.id.expect("existing finding always has id");
        let merged_tool = merge_tool_list(&existing.tool, &finding.tool);
        let merged_source = merge_vuln_source(existing.vuln_source, finding.vuln_source);
        if finding.severity > existing.severity {
            self.replace_collision_headline(merge_id, finding, &merged_tool, merged_source)?;
            self.replace_finding_evidence(merge_id, &finding.evidence)?;
        } else if existing.tool != merged_tool {
            self.update_collision_tool(merge_id, &merged_tool, merged_source)?;
        }
        self.record_finding_source(merge_id, scan_id, finding)?;
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

    /// Look up an existing finding in the workspace that shares the dedup_key.
    /// Same-scan collisions win over historical rows, preserving old merge
    /// behavior while allowing reruns to add corroborating source rows.
    pub(crate) fn find_collision(
        &self,
        scan_id: &str,
        dedup_key: &str,
        new_fingerprint: &str,
    ) -> Result<Option<Finding>> {
        let mut stmt = self.conn.prepare(
            "select id, scan_id, severity, tool, vuln_source, source_signature, corroboration_count
               from findings
              where dedup_key = ?2
                and not (scan_id = ?1 and fingerprint = ?3)
              order by case when scan_id = ?1 then 0 else 1 end,
                       id asc
              limit 1",
        )?;
        let row = stmt
            .query_row(params![scan_id, dedup_key, new_fingerprint], collision_row)
            .optional()?;
        Ok(row.map(|row| row.into_finding(dedup_key)))
    }
}

struct CollisionRow {
    id: i64,
    scan_id: String,
    severity: String,
    tool: String,
    vuln_source: Option<String>,
    source_signature: Option<String>,
    corroboration_count: i64,
}

impl CollisionRow {
    fn into_finding(self, dedup_key: &str) -> Finding {
        Finding {
            id: Some(self.id),
            scan_id: Some(self.scan_id),
            severity: Severity::try_from(self.severity.as_str()).unwrap_or(Severity::Unknown),
            tool: self.tool,
            vuln_source: self.vuln_source.as_deref().and_then(VulnSource::parse),
            dedup_key: Some(dedup_key.to_string()),
            source_signature: self.source_signature,
            corroboration_count: self.corroboration_count.max(0) as u32,
            ..Finding::default()
        }
    }
}

fn collision_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CollisionRow> {
    Ok(CollisionRow {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        severity: row.get(2)?,
        tool: row.get(3)?,
        vuln_source: row.get(4)?,
        source_signature: row.get(5)?,
        corroboration_count: row.get(6)?,
    })
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
  source_signature, corroboration_count, suppressed, snoozed_until,
  remediation, references_json
)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
        ?16, ?17, ?18, ?19, ?20, ?21)
on conflict(scan_id, fingerprint) do update set
  title = excluded.title,
  severity = excluded.severity,
  message = excluded.message,
  actor_fingerprint = excluded.actor_fingerprint,
  static_proof_state = coalesce(excluded.static_proof_state, findings.static_proof_state),
  vuln_source = coalesce(excluded.vuln_source, findings.vuln_source),
  dedup_key = coalesce(excluded.dedup_key, findings.dedup_key),
  source_signature = coalesce(excluded.source_signature, findings.source_signature),
  corroboration_count = max(findings.corroboration_count, excluded.corroboration_count),
  suppressed = excluded.suppressed,
  snoozed_until = excluded.snoozed_until,
  remediation = excluded.remediation,
  references_json = excluded.references_json
"#;
