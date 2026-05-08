use super::*;

impl ReconWorkspaceStore {
    pub fn upsert_service(
        &self,
        host_id: &str,
        port: u16,
        proto: &str,
        name: Option<&str>,
        banner: Option<&str>,
        state: &str,
        info: Value,
    ) -> Result<ReconService> {
        let id = self
            .conn
            .query_row(
                "select id from services where host_id = ?1 and port = ?2 and proto = ?3",
                params![host_id, port as i64, proto],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        self.conn.execute(
            r#"
            insert into services(id, host_id, port, proto, name, banner, state, info_json)
            values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            on conflict(host_id, port, proto) do update set
              name = excluded.name,
              banner = excluded.banner,
              state = excluded.state,
              info_json = excluded.info_json,
              updated_at = datetime('now')
            "#,
            params![
                id,
                host_id,
                port as i64,
                proto,
                name,
                banner,
                state,
                info.to_string()
            ],
        )?;
        self.get_service(&id)
    }
    pub(crate) fn get_service(&self, id: &str) -> Result<ReconService> {
        self.conn
            .query_row(
                "select id, host_id, port, proto, name, banner, state from services where id = ?1",
                params![id],
                row_to_service,
            )
            .with_context(|| format!("recon could not load persisted service {id}"))
    }
    pub(crate) fn count_services(&self) -> Result<usize> {
        let count = self
            .conn
            .query_row("select count(*) from services", [], |row| {
                row.get::<_, i64>(0)
            })?;
        Ok(count as usize)
    }
}
