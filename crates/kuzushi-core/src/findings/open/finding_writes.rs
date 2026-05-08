use super::*;

impl FindingStore {
    pub fn insert_finding(&self, scan_id: &str, finding: &Finding) -> Result<i64> {
        // Cross-channel dedup: when a finding with the same dedup_key but a
        // different fingerprint already exists in this scan, merge instead
        // of inserting a duplicate row. Higher severity wins; tools merge
        // into a comma-list. Skipped silently when the new finding has no
        // dedup_key (legacy callers).
        if let Some(dedup_key) = finding.dedup_key.as_deref() {
            if let Some(existing) = self.find_collision(scan_id, dedup_key, &finding.fingerprint)? {
                let new_sev = finding.severity;
                let merge_id = existing.id.expect("existing finding always has id");
                let merged_tool = merge_tool_list(&existing.tool, &finding.tool);
                let merged_source = merge_vuln_source(existing.vuln_source, finding.vuln_source);
                if new_sev > existing.severity {
                    // Replace the headline rule_id/title/message with the
                    // higher-severity finding so the operator sees the
                    // dominant one.
                    self.conn.execute(
                        r#"update findings set
                             severity = ?, rule_id = ?, title = ?, message = ?,
                             tool = ?, vuln_source = ?
                           where id = ?"#,
                        params![
                            new_sev.as_str(),
                            finding.rule_id,
                            finding.title,
                            finding.message,
                            merged_tool,
                            merged_source.map(|s| s.as_str()),
                            merge_id,
                        ],
                    )?;
                } else if existing.tool != merged_tool {
                    self.conn.execute(
                        "update findings set tool = ?, vuln_source = ? where id = ?",
                        params![merged_tool, merged_source.map(|s| s.as_str()), merge_id],
                    )?;
                }
                return Ok(merge_id);
            }
        }

        self.conn.execute(
            r#"
            insert into findings(
              scan_id, fingerprint, rule_id, title, severity, file_path,
              start_line, end_line, message, tool, actor_fingerprint,
              static_proof_state, created_at, vuln_source, dedup_key
            )
            values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
            on conflict(scan_id, fingerprint) do update set
              title = excluded.title,
              severity = excluded.severity,
              message = excluded.message,
              actor_fingerprint = excluded.actor_fingerprint,
              static_proof_state = coalesce(excluded.static_proof_state, findings.static_proof_state),
              vuln_source = coalesce(excluded.vuln_source, findings.vuln_source),
              dedup_key = coalesce(excluded.dedup_key, findings.dedup_key)
            "#,
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
            ],
        )?;

        let id: i64 = self.conn.query_row(
            "select id from findings where scan_id = ?1 and fingerprint = ?2",
            params![scan_id, finding.fingerprint],
            |row| row.get(0),
        )?;
        Ok(id)
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
                fingerprint: String::new(),
                rule_id: String::new(),
                title: String::new(),
                severity,
                file_path: String::new(),
                start_line: 0,
                end_line: None,
                message: String::new(),
                tool,
                actor_fingerprint: None,
                static_proof_state: None,
                triage: None,
                verification: None,
                created_at: String::new(),
                vuln_source,
                dedup_key: Some(dedup_key.to_string()),
            }
        }))
    }
}
