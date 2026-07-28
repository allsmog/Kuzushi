use super::*;
use crate::storage_v3::writer_actor::{
    DecisionCommand, StorageWriterActor, VerificationWrite, WriterCommand,
};

impl FindingStore {
    pub fn record_auto_triage(&self, finding_id: i64, triage: &TriageOutcome) -> Result<()> {
        self.record_triage_with_author(finding_id, triage, TriageAuthor::Auto)
    }

    pub fn record_triage_with_author(
        &self,
        finding_id: i64,
        triage: &TriageOutcome,
        author: TriageAuthor,
    ) -> Result<()> {
        self.upsert_triage_for_finding_ids([finding_id], triage, author)
            .map(|_| ())
    }

    pub fn record_auto_triage_for_fingerprint(
        &self,
        fingerprint: &str,
        triage: &TriageOutcome,
    ) -> Result<usize> {
        let ids = self.finding_ids_for_fingerprint(fingerprint)?;
        self.upsert_triage_for_finding_ids(ids, triage, TriageAuthor::Auto)
    }

    fn finding_ids_for_fingerprint(&self, fingerprint: &str) -> Result<Vec<i64>> {
        let mut stmt = self.conn.prepare(
            r#"
                select distinct cast(json_extract(finding_json, '$.id') as integer) as finding_id
                  from finding_observations
                 where finding_json is not null
                   and json_extract(finding_json, '$.fingerprint') = ?1
                 order by finding_id asc
                "#,
        )?;
        let rows = stmt.query_map(params![fingerprint], |row| row.get(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list sibling findings for triage fingerprint")
    }

    fn upsert_triage_for_finding_ids(
        &self,
        finding_ids: impl IntoIterator<Item = i64>,
        triage: &TriageOutcome,
        author: TriageAuthor,
    ) -> Result<usize> {
        let mut updated = 0;
        for finding_id in finding_ids {
            updated += usize::from(self.upsert_triage_for_finding_id(finding_id, triage, author)?);
        }
        Ok(updated)
    }

    fn upsert_triage_for_finding_id(
        &self,
        finding_id: i64,
        triage: &TriageOutcome,
        author: TriageAuthor,
    ) -> Result<bool> {
        if self.triage_update_allowed(finding_id, author)? {
            self.append_review_decision_from_triage(finding_id, triage, author)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn triage_update_allowed(&self, finding_id: i64, author: TriageAuthor) -> Result<bool> {
        let Some(finding) = self.v3_finding_by_projected_id(finding_id)? else {
            anyhow::bail!(
                "finding constraint violation: missing projected finding id {finding_id}"
            );
        };
        if finding.triaged_by == Some(TriageAuthor::Human) && author != TriageAuthor::Human {
            return Ok(false);
        }
        Ok(true)
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
        record.validate_for_persistence()?;
        self.record_v3_verification(finding_id, record)
    }

    /// Fetch the most recent verification record for a finding, if any.
    pub fn get_latest_verification(
        &self,
        finding_id: i64,
    ) -> Result<Option<PersistedVerification>> {
        let Some(target) = self.v3_target_for_finding(finding_id, "verification read")? else {
            return Ok(None);
        };
        self.get_latest_verification_for_stable_fp(&target.stable_fp)
    }

    fn get_latest_verification_for_stable_fp(
        &self,
        stable_fp: &str,
    ) -> Result<Option<PersistedVerification>> {
        let Some(db_path) = &self.db_path else {
            return Ok(None);
        };
        crate::storage_v3::ProjectionDb::open(db_path)?;
        let conn = crate::sqlite_connection::open_file(db_path)?;
        let mut stmt = conn.prepare(
            r#"
            select proof_level, proof_verdict, backend, language,
                   harness_path, crash_evidence, duration_ms, cost_usd,
                   notes_json, created_at, verification_run_id, verified_scan_id,
                   provenance_json
            from verification_events
            where stable_fp = ?1
            order by seq desc
            limit 1
            "#,
        )?;
        let mut rows = stmt.query(params![stable_fp])?;
        if let Some(row) = rows.next()? {
            return latest_verification_from_row(row).map(Some);
        }
        Ok(None)
    }

    pub(crate) fn attach_latest_verifications_to_findings(
        &self,
        findings: &mut [Finding],
    ) -> Result<()> {
        let stable_fps = findings
            .iter()
            .map(|finding| {
                finding
                    .identity_id
                    .clone()
                    .unwrap_or_else(|| finding.fingerprint.clone())
            })
            .collect::<Vec<_>>();
        let verifications = self.latest_verifications_for_stable_fps(&stable_fps)?;
        for finding in findings {
            let stable_fp = finding
                .identity_id
                .as_deref()
                .unwrap_or(&finding.fingerprint);
            finding.verification = verifications.get(stable_fp).cloned();
        }
        Ok(())
    }

    fn latest_verifications_for_stable_fps(
        &self,
        stable_fps: &[String],
    ) -> Result<std::collections::BTreeMap<String, PersistedVerification>> {
        if stable_fps.is_empty() || self.db_path.is_none() {
            return Ok(std::collections::BTreeMap::new());
        }
        let requested = serde_json::to_string(stable_fps)?;
        let mut stmt = self.conn.prepare(
            r#"
            with ranked as (
                select stable_fp, proof_level, proof_verdict, backend, language,
                       harness_path, crash_evidence, duration_ms, cost_usd,
                       notes_json, created_at, verification_run_id, verified_scan_id,
                       provenance_json,
                       row_number() over (partition by stable_fp order by seq desc) as event_rank
                  from verification_events
                 where stable_fp in (select value from json_each(?1))
            )
            select stable_fp, proof_level, proof_verdict, backend, language,
                   harness_path, crash_evidence, duration_ms, cost_usd,
                    notes_json, created_at, verification_run_id, verified_scan_id,
                    provenance_json
              from ranked
             where event_rank = 1
            "#,
        )?;
        let mut rows = stmt.query(params![requested])?;
        let mut verifications = std::collections::BTreeMap::new();
        while let Some(row) = rows.next()? {
            let stable_fp: String = row.get(0)?;
            verifications.insert(stable_fp, latest_verification_from_row_at(row, 1)?);
        }
        Ok(verifications)
    }
}

impl FindingStore {
    fn record_v3_verification(
        &self,
        finding_id: i64,
        record: &PersistedVerification,
    ) -> Result<i64> {
        let target = self
            .v3_target_for_finding(finding_id, "verification")?
            .context("verification records require a file-backed v3 finding store")?;
        validate_verification_generation(target.scan_id.as_deref(), record)?;
        validate_verification_reproducer(&target.db_path, record)?;
        let write = VerificationWrite {
            stable_fp: target.stable_fp,
            finding_id: Some(finding_id),
            identity_id: target.identity_id,
            verification_run_id: record.verification_run_id.clone(),
            verified_scan_id: record.verified_scan_id.clone(),
            provenance: record.provenance.clone(),
            proof_level: record.proof_level,
            proof_verdict: record.proof_verdict.as_str().to_string(),
            backend: record.backend.as_str().to_string(),
            language: record.language.clone(),
            harness_path: record.harness_path.clone(),
            crash_evidence: record.crash_evidence.clone(),
            duration_ms: record.duration_ms,
            cost_usd_micros: cost_usd_to_micros(record.cost_usd),
            notes: record.notes.clone(),
            actor: "verification".to_string(),
        };
        let receipt = StorageWriterActor::commit_blocking(
            target.event_log_dir,
            target.db_path,
            WriterCommand::Decision(DecisionCommand::RecordVerification(write)),
        )?;
        Ok(receipt.committed_seq as i64)
    }
}

fn validate_verification_generation(
    current_scan_id: Option<&str>,
    record: &PersistedVerification,
) -> Result<()> {
    anyhow::ensure!(
        current_scan_id.is_none_or(|scan_id| !scan_id.trim().is_empty()),
        "finding current generation id is empty"
    );
    if record.provenance.is_none() {
        return Ok(());
    }
    let verified_scan_id = record
        .verified_scan_id
        .as_deref()
        .map(str::trim)
        .filter(|scan_id| !scan_id.is_empty())
        .context("source-bound verification requires its observed discovery run id")?;
    anyhow::ensure!(
        current_scan_id == Some(verified_scan_id),
        "verification belongs to a stale finding generation"
    );
    Ok(())
}

fn validate_verification_reproducer(
    db_path: &std::path::Path,
    record: &PersistedVerification,
) -> Result<()> {
    let Some(reproducer) = record
        .provenance
        .as_ref()
        .and_then(|provenance| provenance.reproducer.as_ref())
    else {
        return Ok(());
    };
    let objects_dir = db_path
        .parent()
        .context("findings projection path has no state directory")?
        .join(crate::workspace::WORKSPACE_OBJECTS_DIR);
    crate::content_store::ContentStore::open(objects_dir)?
        .get_object(reproducer)
        .context("verification reproducer is missing or corrupt")?;
    Ok(())
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
    let provenance_json: Option<String> = row.get(offset + 12)?;
    let provenance = provenance_json
        .map(|json| -> Result<VerificationProvenance> {
            let provenance: VerificationProvenance = serde_json::from_str(&json)
                .context("persisted verification provenance is invalid")?;
            provenance.validate()?;
            Ok(provenance)
        })
        .transpose()?;
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
        verification_run_id: row.get(offset + 10)?,
        verified_scan_id: row.get(offset + 11)?,
        provenance,
        created_at: row.get(offset + 9)?,
    })
}
