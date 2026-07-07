use super::*;

impl StaticEvidenceStore {
    pub fn open(workspace: &WorkspaceTarget) -> Result<Self> {
        workspace.ensure_state_dir()?;
        Self::open_path(static_evidence_path(workspace))
    }

    pub fn open_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let conn = crate::sqlite_connection::open_file(path)?;
        let store = Self {
            conn,
            db_path: path.display().to_string(),
        };
        store.init()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let store = Self {
            conn: Connection::open_in_memory()
                .context("Could not open in-memory static evidence DB")?,
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
            pragma foreign_keys = on;

            create table if not exists static_evidence_nodes (
              id text primary key,
              kind text not null,
              finding_fingerprint text,
              source_path text,
              start_line integer,
              end_line integer,
              content_hash text not null,
              title text not null,
              body text not null,
              metadata_json text not null default '{}',
              indexed_at_unix integer not null
            );
            create index if not exists idx_static_evidence_nodes_kind
              on static_evidence_nodes(kind, indexed_at_unix desc);
            create index if not exists idx_static_evidence_nodes_finding
              on static_evidence_nodes(finding_fingerprint, kind);
            create index if not exists idx_static_evidence_nodes_source
              on static_evidence_nodes(source_path, start_line, end_line);

            create table if not exists static_evidence_edges (
              id text primary key,
              kind text not null,
              from_node_id text not null references static_evidence_nodes(id) on delete cascade,
              to_node_id text not null references static_evidence_nodes(id) on delete cascade,
              finding_fingerprint text,
              metadata_json text not null default '{}',
              created_at_unix integer not null
            );
            create index if not exists idx_static_evidence_edges_from
              on static_evidence_edges(from_node_id, kind);
            create index if not exists idx_static_evidence_edges_to
              on static_evidence_edges(to_node_id, kind);
            create index if not exists idx_static_evidence_edges_finding
              on static_evidence_edges(finding_fingerprint, kind);
            "#,
        )?;
        Ok(())
    }
}
