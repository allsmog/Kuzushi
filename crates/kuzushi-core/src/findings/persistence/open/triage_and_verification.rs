use super::*;
use std::collections::BTreeMap;

impl FindingStore {
    pub fn save_triage(&self, finding_id: i64, triage: &TriageOutcome) -> Result<()> {
        self.save_triage_with_author(finding_id, triage, TriageAuthor::Auto)
    }

    pub fn save_triage_with_author(
        &self,
        finding_id: i64,
        triage: &TriageOutcome,
        author: TriageAuthor,
    ) -> Result<()> {
        self.upsert_triage_for_finding_ids([finding_id], triage, author)
    }

    pub fn save_triage_for_fingerprint(
        &self,
        fingerprint: &str,
        triage: &TriageOutcome,
    ) -> Result<usize> {
        let ids = self.finding_ids_for_fingerprint(fingerprint)?;
        let count = ids.len();
        self.upsert_triage_for_finding_ids(ids, triage, TriageAuthor::Auto)?;
        Ok(count)
    }

    fn finding_ids_for_fingerprint(&self, fingerprint: &str) -> Result<Vec<i64>> {
        let mut stmt = self
            .conn
            .prepare("select id from findings where fingerprint = ?1 order by id asc")?;
        let rows = stmt.query_map(params![fingerprint], |row| row.get(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list sibling findings for triage fingerprint")
    }

    fn upsert_triage_for_finding_ids(
        &self,
        finding_ids: impl IntoIterator<Item = i64>,
        triage: &TriageOutcome,
        author: TriageAuthor,
    ) -> Result<()> {
        let created_at = now_isoish();
        for finding_id in finding_ids {
            self.upsert_triage_for_finding_id(finding_id, triage, author, &created_at)?;
        }
        Ok(())
    }

    fn upsert_triage_for_finding_id(
        &self,
        finding_id: i64,
        triage: &TriageOutcome,
        author: TriageAuthor,
        created_at: &str,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            insert into triage(
              finding_id, verdict, confidence, rationale, created_at, cost_usd, triaged_by
            )
            values (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            on conflict(finding_id) do update set
              verdict = excluded.verdict,
              confidence = excluded.confidence,
              rationale = excluded.rationale,
              created_at = excluded.created_at,
              cost_usd = excluded.cost_usd,
              triaged_by = excluded.triaged_by
            where coalesce(triage.triaged_by, 'auto') != 'human'
               or excluded.triaged_by = 'human'
            "#,
            params![
                finding_id,
                triage.verdict.as_str(),
                triage.confidence,
                triage.rationale,
                created_at,
                triage.cost_usd,
                author.as_str(),
            ],
        )?;
        Ok(())
    }

    /// Persist an empirical verification outcome alongside its finding.
    /// Each call appends a new row — the same finding can be verified
    /// multiple times (e.g. as the harness improves) and the latest row
    /// wins by `created_at desc`.
    pub fn save_verification(
        &self,
        finding_id: i64,
        record: &PersistedVerification,
    ) -> Result<i64> {
        let notes_json = serde_json::to_string(&record.notes)
            .context("Could not serialize verification notes")?;
        self.conn.execute(
            r#"
            insert into verifications(
              finding_id, proof_level, proof_verdict, backend, language,
              harness_path, crash_evidence, duration_ms, cost_usd,
              notes_json, created_at
            )
            values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            params![
                finding_id,
                record.proof_level as i64,
                record.proof_verdict.as_str(),
                record.backend.as_str(),
                record.language.as_deref(),
                record.harness_path.as_deref(),
                record.crash_evidence.as_deref(),
                record.duration_ms as i64,
                record.cost_usd,
                notes_json,
                now_isoish(),
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Fetch the most recent verification record for a finding, if any.
    pub fn get_latest_verification(
        &self,
        finding_id: i64,
    ) -> Result<Option<PersistedVerification>> {
        let mut stmt = self.conn.prepare(
            r#"
            select proof_level, proof_verdict, backend, language,
                   harness_path, crash_evidence, duration_ms, cost_usd,
                   notes_json, created_at
            from verifications
            where finding_id = ?1
            order by created_at desc, id desc
            limit 1
            "#,
        )?;
        let mut rows = stmt.query(params![finding_id])?;
        if let Some(row) = rows.next()? {
            return latest_verification_from_row(row).map(Some);
        }
        Ok(None)
    }

    pub(crate) fn attach_latest_verifications_to_findings(
        &self,
        findings: &mut [Finding],
    ) -> Result<()> {
        let verification_by_id = self.latest_verifications_by_finding_id(finding_ids(findings))?;
        for finding in findings {
            if let Some(id) = finding.id {
                finding.verification = verification_by_id.get(&id).cloned();
            }
        }
        Ok(())
    }

    fn latest_verifications_by_finding_id(
        &self,
        finding_ids: Vec<i64>,
    ) -> Result<BTreeMap<i64, PersistedVerification>> {
        if finding_ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        let placeholders = vec!["?"; finding_ids.len()].join(", ");
        let sql = format!(
            r#"
            select v.finding_id, v.proof_level, v.proof_verdict, v.backend,
                   v.language, v.harness_path, v.crash_evidence, v.duration_ms,
                   v.cost_usd, v.notes_json, v.created_at
              from verifications v
             where v.finding_id in ({placeholders})
               and v.id = (
                   select latest.id
                     from verifications latest
                    where latest.finding_id = v.finding_id
                    order by latest.created_at desc, latest.id desc
                    limit 1
               )
             order by v.finding_id asc
            "#
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(finding_ids.iter()))?;
        let mut by_id = BTreeMap::new();
        while let Some(row) = rows.next()? {
            let finding_id: i64 = row.get(0)?;
            let verification = latest_verification_from_row_at(row, 1)
                .context("Could not load latest verification")?;
            by_id.insert(finding_id, verification);
        }
        Ok(by_id)
    }
}

fn latest_verification_from_row(row: &rusqlite::Row<'_>) -> Result<PersistedVerification> {
    latest_verification_from_row_at(row, 0)
}

fn latest_verification_from_row_at(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> Result<PersistedVerification> {
    let notes_json: String = row.get(offset + 8)?;
    let notes: Vec<String> = serde_json::from_str(&notes_json).unwrap_or_default();
    let proof_verdict_str: String = row.get(offset + 1)?;
    let backend_str: String = row.get(offset + 2)?;
    Ok(PersistedVerification {
        proof_level: row.get::<_, i64>(offset)? as u8,
        proof_verdict: PersistedProofVerdict::from_str(&proof_verdict_str).ok_or_else(|| {
            anyhow::anyhow!("unknown persisted proof verdict {proof_verdict_str:?}")
        })?,
        backend: PersistedSandboxBackend::from_str(&backend_str)
            .ok_or_else(|| anyhow::anyhow!("unknown persisted sandbox backend {backend_str:?}"))?,
        language: row.get::<_, Option<String>>(offset + 3)?,
        harness_path: row.get::<_, Option<String>>(offset + 4)?,
        crash_evidence: row.get::<_, Option<String>>(offset + 5)?,
        duration_ms: row.get::<_, i64>(offset + 6)? as u64,
        cost_usd: row.get(offset + 7)?,
        notes,
        created_at: row.get(offset + 9)?,
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
