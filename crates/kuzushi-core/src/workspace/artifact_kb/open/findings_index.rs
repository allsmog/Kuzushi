use super::*;

const FINDINGS_CHECKPOINT: &str = "finding_observations.created_seq";
const FINDINGS_CURSOR_FINGERPRINT: &str = "finding_observations.cursor_fingerprint";
const MAX_REFRESH_FINDING_ROWS: usize = 128;
const MAX_REFRESH_FINDING_ROW_BYTES: usize = 512 * 1024;
const MAX_REFRESH_FINDING_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FindingRefreshReport {
    pub indexed: usize,
    pub partial: bool,
}

impl ArtifactKnowledgeStore {
    pub fn index_findings_database(&self, workspace: &WorkspaceTarget) -> Result<usize> {
        let findings_path = workspace.findings_db_path();
        if !findings_path.exists() {
            return Ok(0);
        }
        let conn = crate::sqlite_connection::open_file(&findings_path)?;
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

    pub(crate) fn refresh_findings_database(
        &self,
        workspace: &WorkspaceTarget,
    ) -> Result<FindingRefreshReport> {
        let findings_path = workspace.findings_db_path();
        if !findings_path.exists() {
            return Ok(FindingRefreshReport {
                indexed: 0,
                partial: false,
            });
        }
        let conn = crate::sqlite_connection::open_file(&findings_path)?;
        if !sqlite_table_exists(&conn, "finding_observations")? {
            return Ok(FindingRefreshReport {
                indexed: 0,
                partial: false,
            });
        }
        let cursor = self.normalized_findings_cursor(&conn)?;
        let rows = bounded_finding_rows(&conn, cursor.created_seq)?;
        self.ingest_bounded_finding_rows(rows, cursor)
    }

    fn normalized_findings_cursor(&self, findings: &Connection) -> Result<FindingCursor> {
        let cursor = FindingCursor {
            created_seq: self.checkpoint(FINDINGS_CHECKPOINT)?,
            fingerprint: self.state(FINDINGS_CURSOR_FINGERPRINT)?,
        };
        if cursor.created_seq == 0 {
            return Ok(cursor);
        }
        let actual = finding_fingerprint_at(findings, cursor.created_seq)?;
        if actual.is_some() && actual == cursor.fingerprint {
            return Ok(cursor);
        }
        self.reset_findings_cursor()?;
        Ok(FindingCursor::default())
    }

    fn ingest_bounded_finding_rows(
        &self,
        rows: Vec<BoundedFindingRow>,
        mut cursor: FindingCursor,
    ) -> Result<FindingRefreshReport> {
        let partial = rows.len() > MAX_REFRESH_FINDING_ROWS || self.has_quarantined_findings()?;
        let mut budget = FindingIngestBudget::new(partial);
        for row in rows.into_iter().take(MAX_REFRESH_FINDING_ROWS) {
            if !budget.accept(&row) {
                break;
            }
            cursor = row.cursor();
            if row.raw.is_none() {
                self.quarantine_finding(&row)?;
                continue;
            }
            let raw = row.raw.expect("bounded finding row was checked above");
            let finding = serde_json::from_str::<crate::Finding>(&raw)
                .context("Could not parse v3 finding for artifact KB")?;
            self.upsert_record(&finding_record(&finding.try_into()?))?;
            budget.indexed += 1;
        }
        self.set_findings_cursor(&cursor)?;
        Ok(budget.report())
    }

    fn checkpoint(&self, key: &str) -> Result<i64> {
        self.conn
            .query_row(
                "select checkpoint_value from artifact_kb_checkpoints where checkpoint_key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map(|value| value.unwrap_or(0))
            .context("Could not read artifact KB checkpoint")
    }

    fn state(&self, key: &str) -> Result<Option<String>> {
        self.conn
            .query_row(
                "select state_value from artifact_kb_state where state_key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .context("Could not read artifact KB state")
    }

    fn set_findings_cursor(&self, cursor: &FindingCursor) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            r#"
            insert into artifact_kb_checkpoints(checkpoint_key, checkpoint_value)
            values (?1, ?2)
            on conflict(checkpoint_key) do update set checkpoint_value = excluded.checkpoint_value
            "#,
            params![FINDINGS_CHECKPOINT, cursor.created_seq],
        )?;
        if let Some(fingerprint) = &cursor.fingerprint {
            tx.execute(
                r#"
                insert into artifact_kb_state(state_key, state_value) values (?1, ?2)
                on conflict(state_key) do update set state_value = excluded.state_value
                "#,
                params![FINDINGS_CURSOR_FINGERPRINT, fingerprint],
            )?;
        } else {
            tx.execute(
                "delete from artifact_kb_state where state_key = ?1",
                params![FINDINGS_CURSOR_FINGERPRINT],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn reset_findings_cursor(&self) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "delete from artifact_kb_checkpoints where checkpoint_key = ?1",
            params![FINDINGS_CHECKPOINT],
        )?;
        tx.execute(
            "delete from artifact_kb_state where state_key = ?1",
            params![FINDINGS_CURSOR_FINGERPRINT],
        )?;
        tx.execute("delete from artifact_kb_finding_quarantine", [])?;
        remove_indexed_findings(&tx)?;
        tx.commit()?;
        Ok(())
    }

    fn quarantine_finding(&self, row: &BoundedFindingRow) -> Result<()> {
        self.conn.execute(
            r#"
            insert or replace into artifact_kb_finding_quarantine(
              created_seq, fingerprint, reason
            ) values (?1, ?2, 'finding JSON exceeds the per-row refresh budget')
            "#,
            params![row.created_seq, row.fingerprint()],
        )?;
        Ok(())
    }

    fn has_quarantined_findings(&self) -> Result<bool> {
        self.conn
            .query_row(
                "select exists(select 1 from artifact_kb_finding_quarantine limit 1)",
                [],
                |row| row.get(0),
            )
            .context("Could not inspect artifact KB finding quarantine")
    }
}

#[derive(Default)]
struct FindingCursor {
    created_seq: i64,
    fingerprint: Option<String>,
}

struct BoundedFindingRow {
    created_seq: i64,
    bytes: usize,
    raw: Option<String>,
    prefix: String,
}

impl BoundedFindingRow {
    fn fingerprint(&self) -> String {
        finding_fingerprint(self.bytes, &self.prefix)
    }

    fn cursor(&self) -> FindingCursor {
        FindingCursor {
            created_seq: self.created_seq,
            fingerprint: Some(self.fingerprint()),
        }
    }
}

fn bounded_finding_rows(conn: &Connection, checkpoint: i64) -> Result<Vec<BoundedFindingRow>> {
    let mut stmt = conn.prepare(
        r#"
        select created_seq,
               length(cast(finding_json as blob)) as json_bytes,
               case when length(cast(finding_json as blob)) <= ?3 then finding_json end,
               substr(finding_json, 1, 4096)
        from finding_observations
        where finding_json is not null and created_seq > ?1
        order by created_seq asc
        limit ?2
        "#,
    )?;
    let rows = stmt.query_map(
        params![
            checkpoint,
            MAX_REFRESH_FINDING_ROWS as i64 + 1,
            MAX_REFRESH_FINDING_ROW_BYTES as i64,
        ],
        |row| {
            Ok(BoundedFindingRow {
                created_seq: row.get(0)?,
                bytes: row.get::<_, i64>(1)? as usize,
                raw: row.get(2)?,
                prefix: row.get(3)?,
            })
        },
    )?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("Could not read bounded findings for artifact KB")
}

fn finding_fingerprint_at(conn: &Connection, created_seq: i64) -> Result<Option<String>> {
    conn.query_row(
        r#"
        select length(cast(finding_json as blob)), substr(finding_json, 1, 4096)
        from finding_observations
        where finding_json is not null and created_seq = ?1
        "#,
        params![created_seq],
        |row| {
            let bytes = row.get::<_, i64>(0)? as usize;
            let prefix: String = row.get(1)?;
            Ok(finding_fingerprint(bytes, &prefix))
        },
    )
    .optional()
    .context("Could not validate artifact KB findings cursor")
}

fn finding_fingerprint(bytes: usize, prefix: &str) -> String {
    fnv1a_hex(format!("{bytes}\0{prefix}").as_bytes())
}

fn remove_indexed_findings(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    let pattern = format!("{}%", finding_source_path(""));
    tx.execute(
        "delete from artifact_kb_fts where id in (select id from artifact_kb_records where source_path like ?1)",
        params![&pattern],
    )?;
    tx.execute(
        "delete from artifact_kb_records where source_path like ?1",
        params![&pattern],
    )?;
    Ok(())
}

struct FindingIngestBudget {
    indexed: usize,
    consumed_bytes: usize,
    partial: bool,
}

impl FindingIngestBudget {
    fn new(partial: bool) -> Self {
        Self {
            indexed: 0,
            consumed_bytes: 0,
            partial,
        }
    }

    fn accept(&mut self, row: &BoundedFindingRow) -> bool {
        if row.raw.is_none() {
            self.partial = true;
            return true;
        }
        if self.consumed_bytes.saturating_add(row.bytes) > MAX_REFRESH_FINDING_BYTES {
            self.partial = true;
            return false;
        }
        self.consumed_bytes += row.bytes;
        true
    }

    fn report(self) -> FindingRefreshReport {
        FindingRefreshReport {
            indexed: self.indexed,
            partial: self.partial,
        }
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

    #[test]
    fn quarantined_finding_keeps_future_refreshes_partial() {
        let store = ArtifactKnowledgeStore::open_in_memory().unwrap();
        let row = BoundedFindingRow {
            created_seq: 9,
            bytes: MAX_REFRESH_FINDING_ROW_BYTES + 1,
            raw: None,
            prefix: "oversized".to_string(),
        };
        store.quarantine_finding(&row).unwrap();

        assert!(store.has_quarantined_findings().unwrap());
        assert!(
            FindingIngestBudget::new(store.has_quarantined_findings().unwrap())
                .report()
                .partial
        );
    }
}
