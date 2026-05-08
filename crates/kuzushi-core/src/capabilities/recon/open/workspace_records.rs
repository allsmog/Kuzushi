use super::*;

impl ReconWorkspaceStore {
    pub fn ensure_default_workspace(&mut self, target: &Path) -> Result<String> {
        if let Some(id) = self
            .conn
            .query_row(
                "select id from workspaces where name = ?1",
                params!["default"],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            self.conn.execute(
                "update workspaces set last_accessed_at = ?2, updated_at = datetime('now') where id = ?1",
                params![id, now_isoish()],
            )?;
            return Ok(id);
        }
        let id = Uuid::new_v4().to_string();
        let now = now_isoish();
        self.conn.execute(
            r#"
            insert into workspaces(id, name, targets_json, created_at, last_accessed_at, metadata_json)
            values (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                id,
                "default",
                json!([target.display().to_string()]).to_string(),
                now,
                now,
                "{}",
            ],
        )?;
        Ok(id)
    }
}
