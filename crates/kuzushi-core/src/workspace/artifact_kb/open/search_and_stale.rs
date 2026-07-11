use super::*;

const MAX_STALE_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_STALE_RECORDS: usize = 100_000;

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
        let records = self.records_for_staleness()?;
        Ok(records
            .into_iter()
            .filter_map(|record| stale_record(workspace, record))
            .collect())
    }

    fn records_for_staleness(&self) -> Result<Vec<ArtifactKnowledgeRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, source_path, module_id, run_id, content_hash, title,
                   summary, body, refs_json, metadata_json, indexed_at_unix
            from artifact_kb_records
            order by source_path, module_id, title
            limit ?1
            "#,
        )?;
        let records = stmt
            .query_map(params![MAX_STALE_RECORDS as i64 + 1], row_to_record)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list artifact KB records")?;
        anyhow::ensure!(
            records.len() <= MAX_STALE_RECORDS,
            "Artifact KB exceeds the {MAX_STALE_RECORDS}-record staleness limit"
        );
        Ok(records)
    }
}

fn stale_record(
    workspace: &WorkspaceTarget,
    record: ArtifactKnowledgeRecord,
) -> Option<StaleArtifactRecord> {
    if record.metadata.get("sourceKind").and_then(Value::as_str) == Some("finding-row") {
        return None;
    }
    if record.source_path.contains('#') {
        return None;
    }
    let current_hash = current_source_hash(workspace, &record.source_path);
    (current_hash.as_deref() != Some(record.content_hash.as_str())).then_some(StaleArtifactRecord {
        record,
        current_hash,
    })
}

fn current_source_hash(workspace: &WorkspaceTarget, source_path: &str) -> Option<String> {
    let source_path = Path::new(source_path);
    if source_path.is_absolute() {
        return None;
    }
    let path = workspace.root().join(source_path);
    crate::bounded_file::read_regular_bytes_within(workspace.root(), &path, MAX_STALE_SOURCE_BYTES)
        .ok()
        .map(|bytes| fnv1a_hex(&bytes))
}
