use super::*;

impl ReconWorkspaceStore {
    pub fn list_hosts(&self, workspace_id: &str) -> Result<Vec<ReconHost>> {
        let mut stmt = self.conn.prepare(
            "select id, workspace_id, address, hostname, state from hosts where workspace_id = ?1 order by address",
        )?;
        let rows = stmt.query_map(params![workspace_id], row_to_host)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn list_services_for_host(&self, host_id: &str) -> Result<Vec<ReconService>> {
        let mut stmt = self.conn.prepare(
            "select id, host_id, port, proto, name, banner, state from services where host_id = ?1 order by port",
        )?;
        let rows = stmt.query_map(params![host_id], row_to_service)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn list_notes(&self, workspace_id: &str, ntype: Option<&str>) -> Result<Vec<ReconNote>> {
        let sql = if ntype.is_some() {
            "select id, workspace_id, host_id, service_id, ntype, data_json from notes where workspace_id = ?1 and ntype = ?2 order by created_at desc"
        } else {
            "select id, workspace_id, host_id, service_id, ntype, data_json from notes where workspace_id = ?1 order by created_at desc"
        };
        let mut stmt = self.conn.prepare(sql)?;
        let rows = if let Some(ntype) = ntype {
            stmt.query_map(params![workspace_id, ntype], row_to_note)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            stmt.query_map(params![workspace_id], row_to_note)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        Ok(rows)
    }
}
