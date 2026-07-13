use super::*;

impl ArtifactKnowledgeStore {
    pub(crate) fn search_prompt_snippets(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<ArtifactKnowledgeSnippet>> {
        let Some(fts_query) = build_fts_query(query) else {
            return Ok(Vec::new());
        };
        let mut stmt = self.conn.prepare(
            r#"
            select r.source_path, r.module_id, r.run_id, r.title, r.summary,
                   r.refs_json,
                   coalesce(nullif(snippet(artifact_kb_fts, 3, '[', ']', ' ... ', 18), ''), r.summary)
            from artifact_kb_fts
            join artifact_kb_records r on r.id = artifact_kb_fts.id
            where artifact_kb_fts match ?1
            order by bm25(artifact_kb_fts) asc, r.indexed_at_unix desc, r.title asc
            limit ?2
            "#,
        )?;
        let rows = stmt.query_map(params![fts_query, limit.clamp(1, 50) as i64], |row| {
            let refs_json: String = row.get(5)?;
            Ok(ArtifactKnowledgeSnippet {
                source_path: row.get(0)?,
                module_id: row.get(1)?,
                run_id: row.get(2)?,
                title: row.get(3)?,
                summary: row.get(4)?,
                refs: serde_json::from_str(&refs_json).map_err(to_sql_error)?,
                snippet: row.get(6)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not search artifact KB prompt snippets")
    }
}
