use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourceSignature {
    pub size_bytes: u64,
    pub modified_secs: u64,
    pub modified_nanos: u32,
}

impl SourceSignature {
    pub(crate) fn inspect(workspace: &WorkspaceTarget, source_path: &str) -> Result<Option<Self>> {
        let absolute = crate::workspace::validated_workspace_descendant(
            workspace.root(),
            Path::new(source_path),
        )?;
        let metadata = match fs::symlink_metadata(&absolute) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| source_inspection_error(&absolute)),
        };
        anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "Artifact source must not be a symlink: {}",
            absolute.display()
        );
        if !metadata.is_file() {
            return Ok(None);
        }
        Ok(Some(Self::from_metadata(&metadata)?))
    }

    pub(crate) fn from_metadata(metadata: &fs::Metadata) -> Result<Self> {
        let modified = metadata
            .modified()
            .context("Could not read artifact source modification time")?
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Ok(Self {
            size_bytes: metadata.len(),
            modified_secs: modified.as_secs(),
            modified_nanos: modified.subsec_nanos(),
        })
    }
}

impl ArtifactKnowledgeStore {
    pub(crate) fn source_is_current(
        &self,
        source_path: &str,
        signature: SourceSignature,
    ) -> Result<bool> {
        let current = self
            .conn
            .query_row(
                r#"
                select s.size_bytes, s.modified_secs, s.modified_nanos
                from artifact_kb_source_state s
                join artifact_kb_records r on r.id = s.record_id
                join artifact_kb_fts f on f.id = s.record_id
                where s.source_path = ?1
                "#,
                params![source_path],
                |row| {
                    Ok(SourceSignature {
                        size_bytes: row.get::<_, i64>(0)? as u64,
                        modified_secs: row.get::<_, i64>(1)? as u64,
                        modified_nanos: row.get::<_, i64>(2)? as u32,
                    })
                },
            )
            .optional()
            .context("Could not read artifact KB source state")?;
        Ok(current == Some(signature))
    }

    pub(crate) fn mark_source_current(
        &self,
        record_id: &str,
        source_path: &str,
        content_hash: &str,
        signature: SourceSignature,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            insert into artifact_kb_source_state(
              source_path, record_id, size_bytes, modified_secs, modified_nanos
            )
            select ?1, r.id, ?4, ?5, ?6
            from artifact_kb_records r
            join artifact_kb_fts f on f.id = r.id
            where r.id = ?2 and r.content_hash = ?3
            on conflict(source_path) do update set
              record_id = excluded.record_id,
              size_bytes = excluded.size_bytes,
              modified_secs = excluded.modified_secs,
              modified_nanos = excluded.modified_nanos
            "#,
            params![
                source_path,
                record_id,
                content_hash,
                signature.size_bytes as i64,
                signature.modified_secs as i64,
                signature.modified_nanos as i64,
            ],
        )?;
        Ok(())
    }
}

pub(crate) fn write_source_state(
    tx: &rusqlite::Transaction<'_>,
    record: &ArtifactKnowledgeRecord,
    signature: SourceSignature,
) -> Result<()> {
    tx.execute(
        r#"
        insert into artifact_kb_source_state(
          source_path, record_id, size_bytes, modified_secs, modified_nanos
        ) values (?1, ?2, ?3, ?4, ?5)
        on conflict(source_path) do update set
          record_id = excluded.record_id,
          size_bytes = excluded.size_bytes,
          modified_secs = excluded.modified_secs,
          modified_nanos = excluded.modified_nanos
        "#,
        params![
            record.source_path,
            record.id,
            signature.size_bytes as i64,
            signature.modified_secs as i64,
            signature.modified_nanos as i64,
        ],
    )?;
    Ok(())
}

fn source_inspection_error(path: &Path) -> String {
    format!("Could not inspect artifact source {}", path.display())
}
