use super::*;

impl ArtifactKnowledgeStore {
    pub fn upsert_record(&self, record: &ArtifactKnowledgeRecord) -> Result<()> {
        let refs_json =
            serde_json::to_string(&record.refs).context("Could not serialize KB refs")?;
        let metadata_json =
            serde_json::to_string(&record.metadata).context("Could not serialize KB metadata")?;
        self.conn.execute(
            r#"
            insert into artifact_kb_records(
              id, source_path, module_id, run_id, content_hash, title, summary,
              body, refs_json, metadata_json, indexed_at_unix
            )
            values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            on conflict(id) do update set
              source_path = excluded.source_path,
              module_id = excluded.module_id,
              run_id = excluded.run_id,
              content_hash = excluded.content_hash,
              title = excluded.title,
              summary = excluded.summary,
              body = excluded.body,
              refs_json = excluded.refs_json,
              metadata_json = excluded.metadata_json,
              indexed_at_unix = excluded.indexed_at_unix
            "#,
            params![
                record.id,
                record.source_path,
                record.module_id,
                record.run_id,
                record.content_hash,
                record.title,
                record.summary,
                record.body,
                refs_json,
                metadata_json,
                record.indexed_at_unix as i64,
            ],
        )?;
        self.conn.execute(
            "delete from artifact_kb_fts where id = ?1",
            params![record.id],
        )?;
        self.conn.execute(
            r#"
            insert into artifact_kb_fts(id, title, summary, body, refs, metadata)
            values (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                record.id,
                record.title,
                record.summary,
                record.body,
                refs_json,
                metadata_json
            ],
        )?;
        Ok(())
    }

    pub fn get_record(&self, id: &str) -> Result<Option<ArtifactKnowledgeRecord>> {
        self.conn
            .query_row(
                r#"
                select id, source_path, module_id, run_id, content_hash, title,
                       summary, body, refs_json, metadata_json, indexed_at_unix
                from artifact_kb_records
                where id = ?1
                "#,
                params![id],
                row_to_record,
            )
            .optional()
            .context("Could not load artifact KB record")
    }

    pub fn records_for_source(&self, source_path: &str) -> Result<Vec<ArtifactKnowledgeRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, source_path, module_id, run_id, content_hash, title,
                   summary, body, refs_json, metadata_json, indexed_at_unix
            from artifact_kb_records
            where source_path = ?1
            order by module_id, title
            "#,
        )?;
        let records = stmt
            .query_map(params![source_path], row_to_record)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list artifact KB source records")?;
        Ok(records)
    }

    pub fn count_records(&self) -> Result<usize> {
        let count = self
            .conn
            .query_row("select count(*) from artifact_kb_records", [], |row| {
                row.get::<_, i64>(0)
            })?;
        Ok(count as usize)
    }
}
