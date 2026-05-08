use super::*;

pub(crate) fn row_to_patch_result(row: &rusqlite::Row<'_>) -> rusqlite::Result<PatchResult> {
    Ok(PatchResult {
        patch_run_id: row.get(0)?,
        fingerprint: row.get(1)?,
        repo: row.get(2)?,
        diff: row.get(3)?,
        status: patch_status_from_row(row)?,
        iterations: row.get::<_, i64>(5)? as usize,
        build_command: row.get(6)?,
        test_command: row.get(7)?,
        worktree_path: row.get(8)?,
        cost_usd: row.get(9)?,
        validator_log: row.get(10)?,
        history: patch_history_from_row(row)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
    })
}

fn patch_status_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PatchStatus> {
    let status: String = row.get(4)?;
    PatchStatus::try_from(status.as_str()).map_err(to_sql_error)
}

fn patch_history_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Vec<PatchAttempt>> {
    let history_json: String = row.get(11)?;
    serde_json::from_str::<Vec<PatchAttempt>>(&history_json)
        .map_err(|error| to_sql_error(anyhow::Error::new(error)))
}
