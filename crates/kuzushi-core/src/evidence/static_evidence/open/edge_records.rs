use super::*;

impl StaticEvidenceStore {
    pub fn upsert_edge(&self, edge: &StaticEvidenceEdge) -> Result<()> {
        validate_edge(edge)?;
        let metadata_json = serde_json::to_string(&edge.metadata)
            .context("Could not serialize evidence metadata")?;
        self.conn.execute(
            r#"
            insert into static_evidence_edges(
              id, kind, from_node_id, to_node_id, finding_fingerprint,
              metadata_json, created_at_unix
            )
            values (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            on conflict(id) do update set
              kind = excluded.kind,
              from_node_id = excluded.from_node_id,
              to_node_id = excluded.to_node_id,
              finding_fingerprint = excluded.finding_fingerprint,
              metadata_json = excluded.metadata_json,
              created_at_unix = excluded.created_at_unix
            "#,
            params![
                edge.id,
                edge.kind.as_str(),
                edge.from_node_id,
                edge.to_node_id,
                edge.finding_fingerprint,
                metadata_json,
                edge.created_at_unix as i64,
            ],
        )?;
        Ok(())
    }

    pub fn get_edge(&self, id: &str) -> Result<Option<StaticEvidenceEdge>> {
        self.conn
            .query_row(
                r#"
                select id, kind, from_node_id, to_node_id, finding_fingerprint,
                       metadata_json, created_at_unix
                from static_evidence_edges
                where id = ?1
                "#,
                params![id],
                row_to_edge,
            )
            .optional()
            .context("Could not fetch static evidence edge")
    }

    pub fn edges_for_node(&self, node_id: &str) -> Result<Vec<StaticEvidenceEdge>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, kind, from_node_id, to_node_id, finding_fingerprint,
                   metadata_json, created_at_unix
            from static_evidence_edges
            where from_node_id = ?1 or to_node_id = ?1
            order by kind, id
            "#,
        )?;
        let rows = stmt.query_map(params![node_id], row_to_edge)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list static evidence edges")
    }
}
