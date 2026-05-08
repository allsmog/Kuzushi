use super::*;

impl ArtifactKnowledgeStore {
    pub fn open(workspace: &WorkspaceTarget) -> Result<Self> {
        workspace.ensure_state_dir()?;
        Self::open_path(artifact_kb_path(workspace))
    }

    pub fn open_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Could not create {}", parent.display()))?;
        }
        let conn =
            Connection::open(path).with_context(|| format!("Could not open {}", path.display()))?;
        let store = Self {
            conn,
            db_path: path.display().to_string(),
        };
        store.init()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let store = Self {
            conn: Connection::open_in_memory().context("Could not open in-memory artifact KB")?,
            db_path: ":memory:".to_string(),
        };
        store.init()?;
        Ok(store)
    }

    pub fn db_path(&self) -> &str {
        &self.db_path
    }

    pub fn init(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            create table if not exists artifact_kb_records (
              id text primary key,
              source_path text not null,
              module_id text not null,
              run_id text,
              content_hash text not null,
              title text not null,
              summary text not null,
              body text not null,
              refs_json text not null default '[]',
              metadata_json text not null default '{}',
              indexed_at_unix integer not null
            );
            create index if not exists idx_artifact_kb_source
              on artifact_kb_records(source_path, module_id, run_id);
            create index if not exists idx_artifact_kb_module
              on artifact_kb_records(module_id, indexed_at_unix desc);

            create virtual table if not exists artifact_kb_fts using fts5(
              id unindexed,
              title,
              summary,
              body,
              refs,
              metadata,
              tokenize = 'unicode61'
            );
            "#,
        )?;
        Ok(())
    }
}
