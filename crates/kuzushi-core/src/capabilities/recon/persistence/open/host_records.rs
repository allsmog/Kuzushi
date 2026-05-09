use super::*;

impl ReconWorkspaceStore {
    pub fn upsert_host(
        &self,
        workspace_id: &str,
        address: &str,
        hostname: Option<&str>,
        state: &str,
        metadata: Value,
    ) -> Result<ReconHost> {
        let id = self
            .conn
            .query_row(
                "select id from hosts where workspace_id = ?1 and address = ?2",
                params![workspace_id, address],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        self.conn.execute(
            r#"
            insert into hosts(id, workspace_id, address, hostname, state, metadata_json)
            values (?1, ?2, ?3, ?4, ?5, ?6)
            on conflict(workspace_id, address) do update set
              hostname = excluded.hostname,
              state = excluded.state,
              metadata_json = excluded.metadata_json,
              updated_at = datetime('now')
            "#,
            params![
                id,
                workspace_id,
                address,
                hostname,
                state,
                metadata.to_string()
            ],
        )?;
        self.get_host(&id)
    }
    pub(crate) fn get_host(&self, id: &str) -> Result<ReconHost> {
        self.conn
            .query_row(
                "select id, workspace_id, address, hostname, state from hosts where id = ?1",
                params![id],
                row_to_host,
            )
            .with_context(|| format!("recon could not load persisted host {id}"))
    }
    pub(crate) fn count_hosts(&self) -> Result<usize> {
        let count = self
            .conn
            .query_row("select count(*) from hosts", [], |row| row.get::<_, i64>(0))?;
        Ok(count as usize)
    }
}
