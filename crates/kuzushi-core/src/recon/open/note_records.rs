use super::*;

impl ReconWorkspaceStore {
    pub fn create_note(
        &self,
        workspace_id: &str,
        host_id: Option<&str>,
        service_id: Option<&str>,
        ntype: &str,
        data: Value,
    ) -> Result<ReconNote> {
        let id = Uuid::new_v4().to_string();
        self.conn.execute(
            r#"
            insert into notes(id, workspace_id, host_id, service_id, ntype, data_json)
            values (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                id,
                workspace_id,
                host_id,
                service_id,
                ntype,
                data.to_string()
            ],
        )?;
        self.get_note(&id)
    }
    pub(crate) fn get_note(&self, id: &str) -> Result<ReconNote> {
        self.conn
            .query_row(
                "select id, workspace_id, host_id, service_id, ntype, data_json from notes where id = ?1",
                params![id],
                row_to_note,
            )
            .with_context(|| format!("recon could not load persisted note {id}"))
    }
}
