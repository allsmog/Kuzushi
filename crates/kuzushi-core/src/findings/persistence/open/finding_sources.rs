use super::*;
use std::collections::BTreeMap;

impl FindingStore {
    pub(crate) fn record_finding_source(
        &self,
        finding_id: i64,
        scan_id: &str,
        finding: &Finding,
    ) -> Result<()> {
        let source_signature = finding_source_signature(finding);
        let seen_at = finding_seen_at(finding);
        self.conn.execute(
            r#"
            insert into finding_sources(
              finding_id, tool, vuln_source, source_signature,
              first_scan_id, last_scan_id, first_seen_at, last_seen_at
            )
            values (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?6)
            on conflict(finding_id, tool, source_signature) do update set
              vuln_source = coalesce(excluded.vuln_source, finding_sources.vuln_source),
              last_scan_id = excluded.last_scan_id,
              last_seen_at = excluded.last_seen_at
            "#,
            params![
                finding_id,
                &finding.tool,
                finding.vuln_source.map(|source| source.as_str()),
                &source_signature,
                scan_id,
                seen_at,
            ],
        )?;
        self.refresh_finding_source_rollup(finding_id, &source_signature)
    }

    pub(crate) fn attach_sources_to_findings(&self, findings: &mut [Finding]) -> Result<()> {
        let sources_by_id = self.finding_sources_by_id(finding_ids(findings))?;
        for finding in findings {
            if let Some(id) = finding.id {
                finding.sources = sources_by_id.get(&id).cloned().unwrap_or_default();
                if !finding.sources.is_empty() {
                    finding.corroboration_count = finding.sources.len() as u32;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn attach_sources_to_finding(&self, finding: Option<&mut Finding>) -> Result<()> {
        if let Some(finding) = finding {
            if let Some(id) = finding.id {
                finding.sources = self.finding_sources(id)?;
                if !finding.sources.is_empty() {
                    finding.corroboration_count = finding.sources.len() as u32;
                }
            }
        }
        Ok(())
    }

    fn refresh_finding_source_rollup(&self, finding_id: i64, source_signature: &str) -> Result<()> {
        self.conn.execute(
            r#"
            update findings
               set source_signature = coalesce(source_signature, ?2),
                   corroboration_count = (
                     select count(*)
                       from finding_sources
                      where finding_id = ?1
                   )
             where id = ?1
            "#,
            params![finding_id, source_signature],
        )?;
        Ok(())
    }

    fn finding_sources_by_id(
        &self,
        finding_ids: Vec<i64>,
    ) -> Result<BTreeMap<i64, Vec<FindingSource>>> {
        if finding_ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        let placeholders = vec!["?"; finding_ids.len()].join(", ");
        let sql = format!(
            r#"
            select finding_id, tool, vuln_source, source_signature,
                   first_scan_id, last_scan_id, first_seen_at, last_seen_at
              from finding_sources
             where finding_id in ({placeholders})
             order by finding_id asc, tool asc, source_signature asc
            "#
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(finding_ids.iter()), |row| {
            let finding_id: i64 = row.get(0)?;
            Ok((finding_id, row_to_finding_source(row, 1)?))
        })?;
        let mut grouped = BTreeMap::<i64, Vec<FindingSource>>::new();
        for row in rows {
            let (finding_id, source) = row.context("Could not load finding source")?;
            grouped.entry(finding_id).or_default().push(source);
        }
        Ok(grouped)
    }

    fn finding_sources(&self, finding_id: i64) -> Result<Vec<FindingSource>> {
        let mut stmt = self.conn.prepare(
            r#"
            select tool, vuln_source, source_signature,
                   first_scan_id, last_scan_id, first_seen_at, last_seen_at
              from finding_sources
             where finding_id = ?1
             order by tool asc, source_signature asc
            "#,
        )?;
        let rows = stmt.query_map(params![finding_id], |row| row_to_finding_source(row, 0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not load finding sources")
    }
}

fn finding_source_signature(finding: &Finding) -> String {
    finding.source_signature.clone().unwrap_or_else(|| {
        let cwe = extract_cwe(&finding.rule_id, &finding.title, &finding.message);
        compute_source_signature(
            &finding.file_path,
            finding.start_line,
            cwe.as_deref().or(Some(finding.title.as_str())),
        )
    })
}

fn finding_seen_at(finding: &Finding) -> &str {
    if finding.created_at.trim().is_empty() {
        return "unknown";
    }
    &finding.created_at
}

fn row_to_finding_source(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<FindingSource> {
    let vuln_source: Option<String> = row.get(offset + 1)?;
    Ok(FindingSource {
        tool: row.get(offset)?,
        vuln_source: vuln_source.as_deref().and_then(VulnSource::parse),
        source_signature: row.get(offset + 2)?,
        first_scan_id: row.get(offset + 3)?,
        last_scan_id: row.get(offset + 4)?,
        first_seen_at: row.get(offset + 5)?,
        last_seen_at: row.get(offset + 6)?,
    })
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
