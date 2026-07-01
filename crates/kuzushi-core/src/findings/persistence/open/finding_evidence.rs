use super::*;
use std::collections::BTreeMap;

impl FindingStore {
    pub(crate) fn replace_finding_evidence(
        &self,
        finding_id: i64,
        evidence: &[FindingEvidence],
    ) -> Result<()> {
        self.conn.execute(
            "delete from finding_evidence where finding_id = ?1",
            params![finding_id],
        )?;
        for (ordinal, item) in evidence.iter().enumerate() {
            self.conn.execute(
                r#"
                insert into finding_evidence(
                  finding_id, ordinal, kind, file_path, line, snippet, rationale, confidence,
                  request_blob, response_blob
                )
                values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                "#,
                params![
                    finding_id,
                    ordinal as i64,
                    &item.kind,
                    &item.file_path,
                    item.line,
                    &item.snippet,
                    &item.rationale,
                    item.confidence,
                    &item.request_blob,
                    &item.response_blob,
                ],
            )?;
        }
        Ok(())
    }

    pub(crate) fn attach_evidence_to_findings(&self, findings: &mut [Finding]) -> Result<()> {
        let evidence_by_id = self.finding_evidence_by_id(finding_ids(findings))?;
        for finding in findings {
            if let Some(id) = finding.id {
                finding.evidence = evidence_by_id.get(&id).cloned().unwrap_or_default();
            }
        }
        Ok(())
    }

    pub(crate) fn attach_evidence_to_finding(&self, finding: Option<&mut Finding>) -> Result<()> {
        if let Some(finding) = finding {
            if let Some(id) = finding.id {
                finding.evidence = self.finding_evidence(id)?;
            }
        }
        Ok(())
    }

    fn finding_evidence_by_id(
        &self,
        finding_ids: Vec<i64>,
    ) -> Result<BTreeMap<i64, Vec<FindingEvidence>>> {
        if finding_ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        let placeholders = vec!["?"; finding_ids.len()].join(", ");
        let sql = format!(
            r#"
            select finding_id, kind, file_path, line, snippet, rationale, confidence,
                   request_blob, response_blob
              from finding_evidence
             where finding_id in ({placeholders})
             order by finding_id asc, ordinal asc
            "#
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(finding_ids.iter()), |row| {
            let finding_id: i64 = row.get(0)?;
            Ok((finding_id, row_to_finding_evidence(row, 1)?))
        })?;
        let mut grouped = BTreeMap::<i64, Vec<FindingEvidence>>::new();
        for row in rows {
            let (finding_id, evidence) = row.context("Could not load finding evidence")?;
            grouped.entry(finding_id).or_default().push(evidence);
        }
        Ok(grouped)
    }

    fn finding_evidence(&self, finding_id: i64) -> Result<Vec<FindingEvidence>> {
        let mut stmt = self.conn.prepare(
            r#"
            select kind, file_path, line, snippet, rationale, confidence,
                   request_blob, response_blob
              from finding_evidence
             where finding_id = ?1
             order by ordinal asc
            "#,
        )?;
        let rows = stmt.query_map(params![finding_id], |row| row_to_finding_evidence(row, 0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not load finding evidence")
    }
}

fn finding_ids(findings: &[Finding]) -> Vec<i64> {
    let mut ids = findings
        .iter()
        .filter_map(|finding| finding.id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn row_to_finding_evidence(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<FindingEvidence> {
    let confidence: i64 = row.get(offset + 5)?;
    Ok(FindingEvidence {
        kind: row.get(offset)?,
        file_path: row.get(offset + 1)?,
        line: row.get(offset + 2)?,
        snippet: row.get(offset + 3)?,
        rationale: row.get(offset + 4)?,
        confidence: confidence.clamp(0, u8::MAX as i64) as u8,
        request_blob: row.get(offset + 6)?,
        response_blob: row.get(offset + 7)?,
    })
}
