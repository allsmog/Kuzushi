use super::*;

impl FindingStore {
    pub fn save_triage(&self, finding_id: i64, triage: &TriageOutcome) -> Result<()> {
        self.conn.execute(
            r#"
            insert into triage(finding_id, verdict, confidence, rationale, created_at, cost_usd)
            values (?1, ?2, ?3, ?4, ?5, ?6)
            on conflict(finding_id) do update set
              verdict = excluded.verdict,
              confidence = excluded.confidence,
              rationale = excluded.rationale,
              created_at = excluded.created_at,
              cost_usd = excluded.cost_usd
            "#,
            params![
                finding_id,
                triage.verdict.as_str(),
                triage.confidence,
                triage.rationale,
                now_isoish(),
                triage.cost_usd,
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
}

fn latest_verification_from_row(row: &rusqlite::Row<'_>) -> Result<PersistedVerification> {
    let notes_json: String = row.get(8)?;
    let notes: Vec<String> = serde_json::from_str(&notes_json).unwrap_or_default();
    let proof_verdict_str: String = row.get(1)?;
    let backend_str: String = row.get(2)?;
    Ok(PersistedVerification {
        proof_level: row.get::<_, i64>(0)? as u8,
        proof_verdict: PersistedProofVerdict::from_str(&proof_verdict_str)
            .unwrap_or(PersistedProofVerdict::NotReproduced),
        backend: PersistedSandboxBackend::from_str(&backend_str)
            .unwrap_or(PersistedSandboxBackend::Plain),
        language: row.get::<_, Option<String>>(3)?,
        harness_path: row.get::<_, Option<String>>(4)?,
        crash_evidence: row.get::<_, Option<String>>(5)?,
        duration_ms: row.get::<_, i64>(6)? as u64,
        cost_usd: row.get(7)?,
        notes,
        created_at: row.get(9)?,
    })
}
