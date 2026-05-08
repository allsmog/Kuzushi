use super::prelude::*;
use super::*;

impl StaticEvidenceStore {
    pub fn open(workspace: &WorkspaceTarget) -> Result<Self> {
        workspace.ensure_state_dir()?;
        Self::open_path(static_evidence_path(workspace))
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
