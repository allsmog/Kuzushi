use super::*;

impl ArtifactKnowledgeStore {
    pub fn index_findings_database(&self, workspace: &WorkspaceTarget) -> Result<usize> {
        let findings_path = workspace.findings_db_path();
        if !findings_path.exists() {
            return Ok(0);
        }
        let conn = Connection::open(&findings_path)
            .with_context(|| format!("Could not open {}", findings_path.display()))?;
        if !sqlite_table_exists(&conn, "findings")? {
            return Ok(0);
        }
        let mut stmt = conn.prepare(
            r#"
            select scan_id, fingerprint, rule_id, title, severity, file_path,
                   start_line, end_line, message, tool, created_at
            from findings
            order by scan_id, id
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            let scan_id: String = row.get(0)?;
            let fingerprint: String = row.get(1)?;
            let rule_id: String = row.get(2)?;
            let title: String = row.get(3)?;
            let severity: String = row.get(4)?;
            let file_path: String = row.get(5)?;
            let start_line: i64 = row.get(6)?;
            let end_line: Option<i64> = row.get(7)?;
            let message: String = row.get(8)?;
            let tool: String = row.get(9)?;
            let created_at: String = row.get(10)?;
            Ok((
                scan_id,
                fingerprint,
                rule_id,
                title,
                severity,
                file_path,
                start_line,
                end_line,
                message,
                tool,
                created_at,
            ))
        })?;

        let mut indexed = 0usize;
        for row in rows {
            let (
                scan_id,
                fingerprint,
                rule_id,
                title,
                severity,
                file_path,
                start_line,
                end_line,
                message,
                tool,
                created_at,
            ) = row.context("Could not read persisted finding for artifact KB")?;
            let refs = vec![format!("{file_path}:{start_line}")];
            let body = format!(
                "{title}\nRule: {rule_id}\nSeverity: {severity}\nLocation: {file_path}:{start_line}{}\n\n{message}",
                end_line
                    .map(|line| format!("-{line}"))
                    .unwrap_or_default()
            );
            let source_path = format!(".kuzushi/v2/findings.sqlite3#finding/{}", fingerprint);
            let record = ArtifactKnowledgeRecord::from_body(
                source_path,
                tool,
                Some(scan_id),
                title,
                body,
                refs,
                json!({
                    "sourceKind": "finding-row",
                    "fingerprint": fingerprint,
                    "ruleId": rule_id,
                    "severity": severity,
                    "createdAt": created_at,
                }),
            );
            self.upsert_record(&record)?;
            indexed += 1;
        }
        Ok(indexed)
    }
}
