use super::*;
use crate::storage_v3::writer_actor::{
    DecisionCommand, PatchLifecycleWrite, StorageWriterActor, WriterCommand,
};

impl FindingStore {
    pub fn patch_lifecycle_stable_fp(&self, fingerprint: &str) -> Result<String> {
        self.v3_target_for_fingerprint(fingerprint, "patch lifecycle identity")?
            .map(|target| target.stable_fp)
            .context("patch lifecycle identity requires a file-backed v3 finding store")
    }

    pub fn insert_patch_lifecycle_record(&self, record: &PatchLifecycleRecord) -> Result<()> {
        let target = self
            .v3_target_for_fingerprint(&record.fingerprint, "patch lifecycle")?
            .context("patch lifecycle requires a file-backed v3 finding store")?;
        anyhow::ensure!(
            target.stable_fp == record.stable_fp,
            "patch lifecycle stable finding mismatch: record={} store={}",
            record.stable_fp,
            target.stable_fp
        );
        StorageWriterActor::commit_blocking(
            target.event_log_dir,
            target.db_path,
            WriterCommand::Decision(DecisionCommand::RecordPatchLifecycle(PatchLifecycleWrite {
                record: record.clone(),
            })),
        )?;
        Ok(())
    }

    pub fn get_patch_lifecycle(&self, application_id: &str) -> Result<Option<PatchLifecycleRecord>> {
        let Some(db_path) = &self.db_path else {
            return Ok(None);
        };
        crate::storage_v3::ProjectionDb::open(db_path)?;
        let conn = crate::sqlite_connection::open_file(db_path)?;
        conn.query_row(
            r#"
            select application_id, stable_fp, fingerprint, finding_scan_id,
                   patch_run_id, target,
                   diff_hash, base_commit, touched_files_json, state,
                   reverify_run_id, detail, actor, application_started_at,
                   applied_at, updated_at
              from patch_lifecycle_current
             where application_id = ?1
            "#,
            params![application_id],
            patch_lifecycle_row,
        )
        .optional()
        .context("Could not load patch lifecycle")
    }

    pub fn latest_patch_lifecycle_for_finding(
        &self,
        fingerprint: &str,
    ) -> Result<Option<PatchLifecycleRecord>> {
        self.conn
            .query_row(
                r#"
            select application_id, stable_fp, fingerprint, finding_scan_id,
                   patch_run_id, target,
                   diff_hash, base_commit, touched_files_json, state,
                   reverify_run_id, detail, actor, application_started_at,
                   applied_at, updated_at
              from patch_lifecycle_current
             where fingerprint = ?1 or stable_fp = ?1
             order by latest_seq desc
             limit 1
            "#,
                params![fingerprint],
                patch_lifecycle_row,
            )
            .optional()
            .context("Could not load latest patch lifecycle")
    }

    /// Load the latest lifecycle row for every application in one projection
    /// read. Callers that need engagement-wide remediation truth should use
    /// this instead of issuing one query per finding.
    pub fn list_patch_lifecycle_current(&self) -> Result<Vec<PatchLifecycleRecord>> {
        let Some(db_path) = &self.db_path else {
            return Ok(Vec::new());
        };
        crate::storage_v3::ProjectionDb::open(db_path)?;
        let conn = crate::sqlite_connection::open_file(db_path)?;
        let mut statement = conn.prepare(
            r#"
            select application_id, stable_fp, fingerprint, finding_scan_id,
                   patch_run_id, target,
                   diff_hash, base_commit, touched_files_json, state,
                   reverify_run_id, detail, actor, application_started_at,
                   applied_at, updated_at
              from patch_lifecycle_current
             order by latest_seq desc
            "#,
        )?;
        let rows = statement.query_map([], patch_lifecycle_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not load current patch lifecycles")
    }
}

fn patch_lifecycle_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PatchLifecycleRecord> {
    let touched_files_json: String = row.get(8)?;
    let state: String = row.get(9)?;
    Ok(PatchLifecycleRecord {
        application_id: row.get(0)?,
        stable_fp: row.get(1)?,
        fingerprint: row.get(2)?,
        finding_scan_id: nonempty_optional_string(row, 3)?,
        patch_run_id: row.get(4)?,
        target: row.get(5)?,
        diff_hash: row.get(6)?,
        base_commit: row.get(7)?,
        touched_files: serde_json::from_str(&touched_files_json)
            .map_err(|error| to_sql_error(error.into()))?,
        state: PatchLifecycleState::from_str(&state).ok_or_else(|| {
            to_sql_error(anyhow::anyhow!("unknown patch lifecycle state {state:?}"))
        })?,
        reverify_run_id: row.get(10)?,
        detail: row.get(11)?,
        actor: row.get(12)?,
        application_started_at: row.get(13)?,
        applied_at: nonempty_optional_string(row, 14)?,
        updated_at: row.get(15)?,
    })
}

fn nonempty_optional_string(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<Option<String>> {
    Ok(row
        .get::<_, Option<String>>(index)?
        .filter(|value| !value.is_empty()))
}
