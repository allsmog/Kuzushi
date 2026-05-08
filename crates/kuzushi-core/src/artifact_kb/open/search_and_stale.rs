use super::*;

impl ArtifactKnowledgeStore {
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<ArtifactSearchResult>> {
        let Some(fts_query) = build_fts_query(query) else {
            return Ok(Vec::new());
        };
        let limit = limit.clamp(1, 50) as i64;
        let mut stmt = self.conn.prepare(
            r#"
            select
              r.id, r.source_path, r.module_id, r.run_id, r.content_hash, r.title,
              r.summary, r.body, r.refs_json, r.metadata_json, r.indexed_at_unix,
              bm25(artifact_kb_fts) as score,
              snippet(artifact_kb_fts, 3, '[', ']', ' ... ', 18) as snippet
            from artifact_kb_fts
            join artifact_kb_records r on r.id = artifact_kb_fts.id
            where artifact_kb_fts match ?1
            order by score asc, r.indexed_at_unix desc, r.title asc
            limit ?2
            "#,
        )?;
        let rows = stmt.query_map(params![fts_query, limit], |row| {
            Ok(ArtifactSearchResult {
                record: row_to_record(row)?,
                score: row.get(11)?,
                snippet: row.get(12)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not search artifact KB")
    }

    pub fn stale_records(&self, workspace: &WorkspaceTarget) -> Result<Vec<StaleArtifactRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, source_path, module_id, run_id, content_hash, title,
                   summary, body, refs_json, metadata_json, indexed_at_unix
            from artifact_kb_records
            order by source_path, module_id, title
            "#,
        )?;
        let records = stmt
            .query_map([], row_to_record)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list artifact KB records")?;

        let mut stale = Vec::new();
        for record in records {
            if record
                .metadata
                .get("sourceKind")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind == "finding-row")
            {
                continue;
            }
            if record.source_path.contains('#') {
                continue;
            }
            let path = workspace.root().join(&record.source_path);
            let current_hash = match fs::read(&path) {
                Ok(bytes) => Some(fnv1a_hex(&bytes)),
                Err(_) => None,
            };
            if current_hash.as_deref() != Some(record.content_hash.as_str()) {
                stale.push(StaleArtifactRecord {
                    record,
                    current_hash,
                });
            }
        }
        Ok(stale)
    }
}
