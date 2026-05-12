use super::*;

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
                  finding_id, ordinal, kind, file_path, line, snippet, rationale, confidence
                )
                values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
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
                ],
            )?;
        }
        Ok(())
    }

    pub(crate) fn attach_evidence_to_findings(&self, findings: &mut [Finding]) -> Result<()> {
        for finding in findings {
            if let Some(id) = finding.id {
                finding.evidence = self.finding_evidence(id)?;
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

    fn finding_evidence(&self, finding_id: i64) -> Result<Vec<FindingEvidence>> {
        let mut stmt = self.conn.prepare(
            r#"
            select kind, file_path, line, snippet, rationale, confidence
              from finding_evidence
             where finding_id = ?1
             order by ordinal asc
            "#,
        )?;
        let rows = stmt.query_map(params![finding_id], |row| {
            let confidence: i64 = row.get(5)?;
            Ok(FindingEvidence {
                kind: row.get(0)?,
                file_path: row.get(1)?,
                line: row.get(2)?,
                snippet: row.get(3)?,
                rationale: row.get(4)?,
                confidence: confidence.clamp(0, u8::MAX as i64) as u8,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not load finding evidence")
    }
}
