use super::*;
use crate::content_store::{ContentStore, ObjectKind, ObjectRef};
use crate::identity::Blake3Hash;
use crate::storage_v3::writer_actor::{
    DecisionCommand, PatchAttemptWrite, StorageWriterActor, WriterCommand,
};

impl FindingStore {
    pub fn insert_patch_result(&self, result: &PatchResult) -> Result<()> {
        let history_json =
            serde_json::to_string(&result.history).context("Could not serialize patch history")?;
        self.record_v3_patch_attempt(result, &history_json)?;
        Ok(())
    }

    pub fn get_patch_results_for_finding(&self, fingerprint: &str) -> Result<Vec<PatchResult>> {
        let Some(db_path) = &self.db_path else {
            return Ok(Vec::new());
        };
        crate::storage_v3::ProjectionDb::open(db_path)?;
        let conn = crate::sqlite_connection::open_file(db_path)?;
        let mut stmt = conn.prepare(
            r#"
            select patch_run_id, fingerprint, repo, diff_object, status, iterations,
                   build_command, test_command, worktree_path, cost_usd,
                   validator_log, history_json, created_at, created_at
            from patch_attempt_events
            where fingerprint = ?1
            order by seq desc
            "#,
        )?;
        let rows = stmt.query_map(params![fingerprint], row_to_v3_patch_result)?;
        let mut results = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list v3 patch results")?;
        self.attach_patch_diffs(&mut results)?;
        Ok(results)
    }

    fn record_v3_patch_attempt(&self, result: &PatchResult, history_json: &str) -> Result<()> {
        let target = self
            .v3_target_for_fingerprint(&result.fingerprint, "patch attempt")?
            .context("patch results require a file-backed v3 finding store")?;
        let diff_object = self.patch_diff_object(result.diff.as_deref())?;
        StorageWriterActor::commit_blocking(
            target.event_log_dir,
            target.db_path,
            WriterCommand::Decision(DecisionCommand::RecordPatchAttempt(PatchAttemptWrite {
                stable_fp: target.stable_fp,
                fingerprint: target.fingerprint,
                patch_run_id: result.patch_run_id.clone(),
                repo: result.repo.clone(),
                diff_object: diff_object
                    .as_ref()
                    .map(|object| object.hash.as_str().to_string()),
                diff_size_bytes: diff_object.as_ref().map(|object| object.size_bytes),
                status: result.status.as_str().to_string(),
                iterations: result.iterations as u64,
                build_command: result.build_command.clone(),
                test_command: result.test_command.clone(),
                worktree_path: result.worktree_path.clone(),
                cost_usd_micros: result.cost_usd.map(cost_usd_to_micros),
                validator_log: result.validator_log.clone(),
                history_json: history_json.to_string(),
                actor: "patch-runner".to_string(),
            })),
        )?;
        Ok(())
    }

    fn patch_diff_object(&self, diff: Option<&str>) -> Result<Option<ObjectRef>> {
        let Some(diff) = diff else {
            return Ok(None);
        };
        let Some(db_path) = &self.db_path else {
            return Ok(None);
        };
        let objects_dir = db_path
            .parent()
            .context("v3 index path has no parent for patch diff object store")?
            .join("objects");
        ContentStore::open(objects_dir)?
            .put_bytes(ObjectKind::PatchDiff, diff.as_bytes())
            .map(Some)
    }

    fn attach_patch_diffs(&self, results: &mut [PatchResult]) -> Result<()> {
        let Some(db_path) = &self.db_path else {
            return Ok(());
        };
        let objects_dir = db_path
            .parent()
            .context("v3 index path has no parent for patch diff object store")?
            .join("objects");
        let store = ContentStore::open(objects_dir)?;
        for result in results {
            let Some(object_hash) = result.diff.as_deref() else {
                continue;
            };
            let hash = Blake3Hash::new(object_hash.to_string())?;
            let bytes = store.get(&hash)?;
            result.diff = Some(String::from_utf8_lossy(&bytes).to_string());
        }
        Ok(())
    }
}

fn row_to_v3_patch_result(row: &rusqlite::Row<'_>) -> rusqlite::Result<PatchResult> {
    let status: String = row.get(4)?;
    let history_json: String = row.get(11)?;
    Ok(PatchResult {
        patch_run_id: row.get(0)?,
        fingerprint: row.get(1)?,
        repo: row.get(2)?,
        diff: row.get(3)?,
        status: PatchStatus::try_from(status.as_str()).map_err(to_sql_error)?,
        iterations: row.get::<_, i64>(5)? as usize,
        build_command: row.get(6)?,
        test_command: row.get(7)?,
        worktree_path: row.get(8)?,
        cost_usd: row.get(9)?,
        validator_log: row.get(10)?,
        history: serde_json::from_str::<Vec<PatchAttempt>>(&history_json)
            .map_err(|error| to_sql_error(anyhow::Error::new(error)))?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
    })
}
