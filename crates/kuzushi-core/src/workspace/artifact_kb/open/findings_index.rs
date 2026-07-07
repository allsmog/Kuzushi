use super::*;

impl ArtifactKnowledgeStore {
    pub fn index_findings_database(&self, workspace: &WorkspaceTarget) -> Result<usize> {
        let findings_path = workspace.findings_db_path();
        if !findings_path.exists() {
            return Ok(0);
        }
        let conn = Connection::open(&findings_path)
            .with_context(|| format!("Could not open {}", findings_path.display()))?;
        if !sqlite_table_exists(&conn, "finding_observations")? {
            return Ok(0);
        }

        let rows = finding_index_rows(&conn)?;
        for row in &rows {
            let record = finding_record(row);
            self.upsert_record(&record)?;
        }
        Ok(rows.len())
    }
}

struct FindingIndexRow {
    scan_id: String,
    fingerprint: String,
    rule_id: String,
    title: String,
    severity: String,
    file_path: String,
    start_line: i64,
    end_line: Option<i64>,
    message: String,
    tool: String,
    created_at: String,
}

impl TryFrom<crate::Finding> for FindingIndexRow {
    type Error = anyhow::Error;

    fn try_from(finding: crate::Finding) -> Result<Self> {
        Ok(Self {
            scan_id: finding.scan_id.unwrap_or_default(),
            fingerprint: finding.fingerprint,
            rule_id: finding.rule_id,
            title: finding.title,
            severity: finding.severity.as_str().to_string(),
            file_path: finding.file_path,
            start_line: i64::from(finding.start_line),
            end_line: finding.end_line.map(i64::from),
            message: finding.message,
            tool: finding.tool,
            created_at: finding.created_at,
        })
    }
}

fn finding_index_rows(conn: &Connection) -> Result<Vec<FindingIndexRow>> {
    let mut stmt = conn.prepare(
        r#"
            select finding_json
            from finding_observations
            where finding_json is not null
            order by run_id, created_seq
            "#,
    )?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("Could not read persisted finding for artifact KB")?;
    rows.into_iter()
        .map(|raw| {
            serde_json::from_str::<crate::Finding>(&raw)
                .context("Could not parse v3 finding for artifact KB")?
                .try_into()
        })
        .collect()
}

fn finding_record(row: &FindingIndexRow) -> ArtifactKnowledgeRecord {
    ArtifactKnowledgeRecord::from_body(
        finding_source_path(&row.fingerprint),
        row.tool.clone(),
        Some(row.scan_id.clone()),
        row.title.clone(),
        finding_body(row),
        vec![format!("{}:{}", row.file_path, row.start_line)],
        json!({
            "sourceKind": "finding-row",
            "fingerprint": row.fingerprint,
            "ruleId": row.rule_id,
            "severity": row.severity,
            "createdAt": row.created_at,
        }),
    )
}

fn finding_body(row: &FindingIndexRow) -> String {
    format!(
        "{}\nRule: {}\nSeverity: {}\nLocation: {}:{}{}\n\n{}",
        row.title,
        row.rule_id,
        row.severity,
        row.file_path,
        row.start_line,
        row.end_line
            .map(|line| format!("-{line}"))
            .unwrap_or_default(),
        row.message
    )
}

fn finding_source_path(fingerprint: &str) -> String {
    format!(
        "{}#finding/{}",
        crate::workspace::workspace_findings_db_path(Path::new(""))
            .to_string_lossy()
            .replace('\\', "/"),
        fingerprint
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_source_path_uses_workspace_findings_db_path() {
        assert_eq!(
            finding_source_path("abc123"),
            format!(
                "{}#finding/abc123",
                crate::workspace::workspace_findings_db_path(Path::new(""))
                    .to_string_lossy()
                    .replace('\\', "/")
            )
        );
    }
}
