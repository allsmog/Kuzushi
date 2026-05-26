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

impl FindingIndexRow {
    fn from_sql_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            scan_id: row.get(0)?,
            fingerprint: row.get(1)?,
            rule_id: row.get(2)?,
            title: row.get(3)?,
            severity: row.get(4)?,
            file_path: row.get(5)?,
            start_line: row.get(6)?,
            end_line: row.get(7)?,
            message: row.get(8)?,
            tool: row.get(9)?,
            created_at: row.get(10)?,
        })
    }
}

fn finding_index_rows(conn: &Connection) -> Result<Vec<FindingIndexRow>> {
    let mut stmt = conn.prepare(
        r#"
            select scan_id, fingerprint, rule_id, title, severity, file_path,
                   start_line, end_line, message, tool, created_at
            from findings
            order by scan_id, id
            "#,
    )?;
    let rows = stmt
        .query_map([], FindingIndexRow::from_sql_row)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("Could not read persisted finding for artifact KB")?;
    Ok(rows)
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
