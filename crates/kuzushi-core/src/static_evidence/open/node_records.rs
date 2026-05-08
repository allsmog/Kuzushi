use super::*;

impl StaticEvidenceStore {
    pub fn upsert_node(&self, node: &StaticEvidenceNode) -> Result<()> {
        validate_node(node)?;
        let metadata_json = serde_json::to_string(&node.metadata)
            .context("Could not serialize evidence metadata")?;
        self.conn.execute(
            r#"
            insert into static_evidence_nodes(
              id, kind, finding_fingerprint, source_path, start_line, end_line,
              content_hash, title, body, metadata_json, indexed_at_unix
            )
            values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            on conflict(id) do update set
              kind = excluded.kind,
              finding_fingerprint = excluded.finding_fingerprint,
              source_path = excluded.source_path,
              start_line = excluded.start_line,
              end_line = excluded.end_line,
              content_hash = excluded.content_hash,
              title = excluded.title,
              body = excluded.body,
              metadata_json = excluded.metadata_json,
              indexed_at_unix = excluded.indexed_at_unix
            "#,
            params![
                node.id,
                node.kind.as_str(),
                node.finding_fingerprint,
                node.source_path,
                node.start_line,
                node.end_line,
                node.content_hash,
                node.title,
                node.body,
                metadata_json,
                node.indexed_at_unix as i64,
            ],
        )?;
        Ok(())
    }

    pub fn get_node(&self, id: &str) -> Result<Option<StaticEvidenceNode>> {
        self.conn
            .query_row(
                r#"
                select id, kind, finding_fingerprint, source_path, start_line, end_line,
                       content_hash, title, body, metadata_json, indexed_at_unix
                from static_evidence_nodes
                where id = ?1
                "#,
                params![id],
                row_to_node,
            )
            .optional()
            .context("Could not fetch static evidence node")
    }

    pub fn list_nodes_for_finding(&self, fingerprint: &str) -> Result<Vec<StaticEvidenceNode>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, kind, finding_fingerprint, source_path, start_line, end_line,
                   content_hash, title, body, metadata_json, indexed_at_unix
            from static_evidence_nodes
            where finding_fingerprint = ?1
            order by kind, source_path, start_line, id
            "#,
        )?;
        let rows = stmt.query_map(params![fingerprint], row_to_node)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list static evidence nodes")
    }
}
