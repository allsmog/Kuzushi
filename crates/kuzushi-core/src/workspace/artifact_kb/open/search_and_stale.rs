use super::*;

const MAX_STALE_SOURCE_BYTES: usize = 16 * 1024 * 1024;
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
        let probes = self.staleness_probes()?;
        let mut stale = Vec::new();
        for probe in probes {
            if let Some(record) = self.stale_record(workspace, probe)? {
                stale.push(record);
            }
        }
        Ok(stale)
    }

    fn staleness_probes(&self) -> Result<Vec<StalenessProbe>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, source_path, content_hash, metadata_json
            from artifact_kb_records
            order by source_path, module_id, title
            limit ?1
            "#,
        )?;
        let probes = stmt
            .query_map(params![MAX_STALE_RECORDS as i64 + 1], row_to_probe)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list artifact KB staleness probes")?;
        anyhow::ensure!(
            probes.len() <= MAX_STALE_RECORDS,
            "Artifact KB exceeds the {MAX_STALE_RECORDS}-record staleness limit"
        );
        Ok(probes)
    }

    fn stale_record(
        &self,
        workspace: &WorkspaceTarget,
        probe: StalenessProbe,
    ) -> Result<Option<StaleArtifactRecord>> {
        if probe.is_virtual() {
            return Ok(None);
        }
        let current_hash = self.current_source_hash(workspace, &probe)?;
        if current_hash.as_deref() == Some(probe.content_hash.as_str()) {
            return Ok(None);
        }
        let Some(record) = self.get_record(&probe.id)? else {
            return Ok(None);
        };
        Ok(Some(StaleArtifactRecord {
            record,
            current_hash,
        }))
    }

    fn current_source_hash(
        &self,
        workspace: &WorkspaceTarget,
        probe: &StalenessProbe,
    ) -> Result<Option<String>> {
        let signature = match SourceSignature::inspect(workspace, &probe.source_path) {
            Ok(Some(signature)) => signature,
            Ok(None) | Err(_) => return Ok(None),
        };
        if self.source_is_current(&probe.source_path, signature)? {
            return Ok(Some(probe.content_hash.clone()));
        }
        let hash = read_current_source_hash(workspace, &probe.source_path);
        if hash.as_deref() == Some(probe.content_hash.as_str()) {
            self.mark_source_current(
                &probe.id,
                &probe.source_path,
                &probe.content_hash,
                signature,
            )?;
        }
        Ok(hash)
    }
}

struct StalenessProbe {
    id: String,
    source_path: String,
    content_hash: String,
    source_kind: Option<String>,
}

impl StalenessProbe {
    fn is_virtual(&self) -> bool {
        self.source_kind.as_deref() == Some("finding-row") || self.source_path.contains('#')
    }
}

fn row_to_probe(row: &rusqlite::Row<'_>) -> rusqlite::Result<StalenessProbe> {
    let metadata_json: String = row.get(3)?;
    let metadata = serde_json::from_str::<Value>(&metadata_json).map_err(to_sql_error)?;
    Ok(StalenessProbe {
        id: row.get(0)?,
        source_path: row.get(1)?,
        content_hash: row.get(2)?,
        source_kind: metadata
            .get("sourceKind")
            .and_then(Value::as_str)
            .map(ToString::to_string),
    })
}

fn read_current_source_hash(workspace: &WorkspaceTarget, source_path: &str) -> Option<String> {
    let source_path = Path::new(source_path);
    if source_path.is_absolute() {
        return None;
    }
    let path = workspace.root().join(source_path);
    crate::bounded_file::read_regular_bytes_within(workspace.root(), &path, MAX_STALE_SOURCE_BYTES)
        .ok()
        .map(|bytes| fnv1a_hex(&bytes))
}
