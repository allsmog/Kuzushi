use super::*;

impl FindingStore {
    pub fn insert_patch_result(&self, result: &PatchResult) -> Result<()> {
        let history_json =
            serde_json::to_string(&result.history).context("Could not serialize patch history")?;
        self.conn.execute(
            r#"
            insert into patch_results(
              patch_run_id, fingerprint, repo, diff, status, iterations,
              build_command, test_command, worktree_path, cost_usd,
              validator_log, history_json
            )
            values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
            params![
                &result.patch_run_id,
                &result.fingerprint,
                &result.repo,
                &result.diff,
                result.status.as_str(),
                result.iterations as i64,
                &result.build_command,
                &result.test_command,
                &result.worktree_path,
                result.cost_usd,
                &result.validator_log,
                history_json,
            ],
        )?;
        Ok(())
    }

    pub fn get_patch_results_for_finding(&self, fingerprint: &str) -> Result<Vec<PatchResult>> {
        let mut stmt = self.conn.prepare(
            r#"
            select patch_run_id, fingerprint, repo, diff, status, iterations,
                   build_command, test_command, worktree_path, cost_usd,
                   validator_log, history_json, created_at, updated_at
            from patch_results
            where fingerprint = ?1
            order by created_at desc
            "#,
        )?;
        let rows = stmt.query_map(params![fingerprint], row_to_patch_result)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list patch results")
    }
}
