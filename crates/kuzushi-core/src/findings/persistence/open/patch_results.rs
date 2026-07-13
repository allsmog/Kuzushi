use super::*;
use crate::content_store::{ContentStore, ObjectKind, ObjectRef};
use crate::identity::Blake3Hash;
use crate::storage_v3::writer_actor::{
    DecisionCommand, PatchAttemptWrite, StorageWriterActor, WriterCommand,
};

impl FindingStore {
    pub fn insert_patch_result(&self, result: &PatchResult) -> Result<()> {
        let cost_usd = validated_patch_cost_usd(result)?;
        let cost_usd_micros = cost_usd.and_then(legacy_cost_usd_micros);
        let history_json =
            serde_json::to_string(&result.history).context("Could not serialize patch history")?;
        self.record_v3_patch_attempt(result, &history_json, cost_usd, cost_usd_micros)?;
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
            select patch_run_id, fingerprint, repo, diff_object, diff_size_bytes, status, iterations,
                   build_command, test_command, worktree_path, cost_usd,
                   provider_spend_unresolved, validator_log, history_json,
                   created_at, created_at
            from patch_attempt_events
            where fingerprint = ?1
            order by seq desc
            "#,
        )?;
        let rows = stmt.query_map(params![fingerprint], row_to_v3_patch_result)?;
        let mut stored_results = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list v3 patch results")?;
        self.attach_patch_diffs(&mut stored_results)?;
        Ok(stored_results
            .into_iter()
            .map(|stored| stored.result)
            .collect())
    }

    fn record_v3_patch_attempt(
        &self,
        result: &PatchResult,
        history_json: &str,
        cost_usd: Option<f64>,
        cost_usd_micros: Option<i64>,
    ) -> Result<()> {
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
                cost_usd,
                cost_usd_micros,
                provider_spend_unresolved: result.provider_spend_unresolved,
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

    fn attach_patch_diffs(&self, results: &mut [StoredPatchResult]) -> Result<()> {
        let Some(db_path) = &self.db_path else {
            return Ok(());
        };
        let objects_dir = db_path
            .parent()
            .context("v3 index path has no parent for patch diff object store")?
            .join("objects");
        let store = ContentStore::open(objects_dir)?;
        for stored in results {
            let Some(object_hash) = stored.result.diff.as_deref() else {
                continue;
            };
            let hash = Blake3Hash::new(object_hash.to_string())?;
            let size_bytes = stored.diff_size_bytes.with_context(|| {
                format!("patch diff object {hash} is missing its recorded size")
            })?;
            let object_ref = ObjectRef {
                kind: ObjectKind::PatchDiff,
                hash,
                size_bytes,
            };
            let bytes = store.get_object(&object_ref)?;
            stored.result.diff = Some(String::from_utf8(bytes).context("Patch diff is not UTF-8")?);
        }
        Ok(())
    }
}

struct StoredPatchResult {
    result: PatchResult,
    diff_size_bytes: Option<u64>,
}

fn row_to_v3_patch_result(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredPatchResult> {
    let status: String = row.get(5)?;
    let cost_usd: Option<f64> = row.get(10)?;
    let stored_unresolved: Option<bool> = row.get(11)?;
    let history_json: String = row.get(13)?;
    let result = PatchResult {
        patch_run_id: row.get(0)?,
        fingerprint: row.get(1)?,
        repo: row.get(2)?,
        diff: row.get(3)?,
        status: PatchStatus::try_from(status.as_str()).map_err(to_sql_error)?,
        iterations: row.get::<_, i64>(6)? as usize,
        build_command: row.get(7)?,
        test_command: row.get(8)?,
        worktree_path: row.get(9)?,
        cost_usd,
        provider_spend_unresolved: stored_unresolved.unwrap_or(false),
        validator_log: row.get(12)?,
        history: serde_json::from_str::<Vec<PatchAttempt>>(&history_json)
            .map_err(|error| to_sql_error(anyhow::Error::new(error)))?,
        created_at: row.get(14)?,
        updated_at: row.get(15)?,
    };
    result.validated_cost_usd().map_err(to_sql_error)?;
    Ok(StoredPatchResult {
        result,
        diff_size_bytes: optional_nonnegative_u64(row, 4)?,
    })
}

fn validated_patch_cost_usd(result: &PatchResult) -> Result<Option<f64>> {
    result.validated_cost_usd()
}

fn legacy_cost_usd_micros(cost_usd: f64) -> Option<i64> {
    let micros = cost_usd * 1_000_000.0;
    let rounded = micros.round();
    (rounded.is_finite() && rounded < i64::MAX as f64).then_some(rounded as i64)
}

fn optional_nonnegative_u64(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<Option<u64>> {
    row.get::<_, Option<i64>>(index)?
        .map(|value| {
            u64::try_from(value).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    index,
                    rusqlite::types::Type::Integer,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("negative object size {value}"),
                    )),
                )
            })
        })
        .transpose()
}

#[cfg(test)]
mod cost_tests {
    use super::*;

    #[test]
    fn patch_cost_validation_rejects_invalid_values_without_rejecting_finite_real_values() {
        for invalid in [-1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(validated_patch_cost_usd(&patch_result(Some(invalid), false)).is_err());
        }
        assert_eq!(
            validated_patch_cost_usd(&patch_result(Some(f64::MAX), false)).unwrap(),
            Some(f64::MAX)
        );
        assert_eq!(legacy_cost_usd_micros(f64::MAX), None);
    }

    #[test]
    fn legacy_micros_are_compatibility_only_and_do_not_replace_exact_cost() {
        assert_eq!(legacy_cost_usd_micros(0.0), Some(0));
        let unresolved = patch_result(Some(0.25), true);
        assert_eq!(validated_patch_cost_usd(&unresolved).unwrap(), Some(0.25));
        assert_eq!(legacy_cost_usd_micros(0.25), Some(250_000));
        assert!(unresolved.validated_cost_usd().is_ok());
    }

    #[test]
    fn legacy_row_without_cost_or_unresolved_bit_stays_unavailable_not_unresolved() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let stored = conn
            .query_row(
                "select 'patch-run', 'fp', '/repo', null, null, 'UNKNOWN', 0,
                        null, null, null, null, null, null, '[]', null, null",
                [],
                row_to_v3_patch_result,
            )
            .unwrap();

        assert_eq!(stored.result.cost_usd, None);
        assert!(!stored.result.provider_spend_unresolved);
        assert_eq!(stored.result.validated_cost_usd().unwrap(), None);
    }

    fn patch_result(cost_usd: Option<f64>, provider_spend_unresolved: bool) -> PatchResult {
        PatchResult {
            patch_run_id: "patch-cost-test".to_string(),
            fingerprint: "fp-test".to_string(),
            repo: "/repo".to_string(),
            diff: None,
            status: PatchStatus::Unknown,
            iterations: 1,
            build_command: None,
            test_command: None,
            worktree_path: None,
            cost_usd,
            provider_spend_unresolved,
            validator_log: None,
            history: Vec::new(),
            created_at: None,
            updated_at: None,
        }
    }
}
