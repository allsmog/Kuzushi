use super::*;

impl FindingStore {
    pub fn insert_scan_run(&self, id: &str, target: &Path, status: &str) -> Result<()> {
        self.conn.execute(
            r#"
            insert into scan_runs(id, target, status, started_at, findings_count)
            values (?1, ?2, ?3, ?4, 0)
            on conflict(id) do update set status = excluded.status
            "#,
            params![id, target.display().to_string(), status, now_isoish()],
        )?;
        Ok(())
    }

    pub fn complete_scan_run(&self, id: &str, status: &str, findings_count: usize) -> Result<()> {
        self.conn.execute(
            r#"
            update scan_runs
            set status = ?2, completed_at = ?3, findings_count = ?4
            where id = ?1
            "#,
            params![id, status, now_isoish(), findings_count as i64],
        )?;
        Ok(())
    }

    pub fn latest_scan_run_id(&self) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id
            from scan_runs
            order by coalesce(completed_at, started_at) desc, started_at desc, id desc
            limit 1
            "#,
        )?;
        match stmt.query_row([], |row| row.get(0)) {
            Ok(id) => Ok(Some(id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error).context("Could not load latest scan run id"),
        }
    }
}
