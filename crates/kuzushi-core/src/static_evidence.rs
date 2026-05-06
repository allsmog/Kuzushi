use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::workspace::WorkspaceTarget;

const STATIC_EVIDENCE_DB_NAME: &str = "static-evidence.sqlite3";

pub const STATIC_EVIDENCE_NODE_KINDS: &[StaticEvidenceNodeKind] = &[
    StaticEvidenceNodeKind::CodeSpan,
    StaticEvidenceNodeKind::ScannerSignal,
    StaticEvidenceNodeKind::Source,
    StaticEvidenceNodeKind::Sink,
    StaticEvidenceNodeKind::DataflowStep,
    StaticEvidenceNodeKind::Sanitizer,
    StaticEvidenceNodeKind::Guard,
    StaticEvidenceNodeKind::AttackSurface,
    StaticEvidenceNodeKind::TriageClaim,
    StaticEvidenceNodeKind::ReportClaim,
];

pub const STATIC_EVIDENCE_EDGE_KINDS: &[StaticEvidenceEdgeKind] = &[
    StaticEvidenceEdgeKind::Supports,
    StaticEvidenceEdgeKind::DerivedFrom,
    StaticEvidenceEdgeKind::FlowsTo,
    StaticEvidenceEdgeKind::GuardedBy,
    StaticEvidenceEdgeKind::SanitizedBy,
    StaticEvidenceEdgeKind::Contradicts,
    StaticEvidenceEdgeKind::ReportedAs,
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StaticEvidenceNodeKind {
    CodeSpan,
    ScannerSignal,
    Source,
    Sink,
    DataflowStep,
    Sanitizer,
    Guard,
    AttackSurface,
    TriageClaim,
    ReportClaim,
}

impl StaticEvidenceNodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CodeSpan => "code_span",
            Self::ScannerSignal => "scanner_signal",
            Self::Source => "source",
            Self::Sink => "sink",
            Self::DataflowStep => "dataflow_step",
            Self::Sanitizer => "sanitizer",
            Self::Guard => "guard",
            Self::AttackSurface => "attack_surface",
            Self::TriageClaim => "triage_claim",
            Self::ReportClaim => "report_claim",
        }
    }
}

impl TryFrom<&str> for StaticEvidenceNodeKind {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value.trim() {
            "code_span" | "code-span" => Ok(Self::CodeSpan),
            "scanner_signal" | "scanner-signal" => Ok(Self::ScannerSignal),
            "source" => Ok(Self::Source),
            "sink" => Ok(Self::Sink),
            "dataflow_step" | "dataflow-step" => Ok(Self::DataflowStep),
            "sanitizer" => Ok(Self::Sanitizer),
            "guard" => Ok(Self::Guard),
            "attack_surface" | "attack-surface" => Ok(Self::AttackSurface),
            "triage_claim" | "triage-claim" => Ok(Self::TriageClaim),
            "report_claim" | "report-claim" => Ok(Self::ReportClaim),
            other => anyhow::bail!("unknown static evidence node kind {other:?}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StaticEvidenceEdgeKind {
    Supports,
    DerivedFrom,
    FlowsTo,
    GuardedBy,
    SanitizedBy,
    Contradicts,
    ReportedAs,
}

impl StaticEvidenceEdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supports => "supports",
            Self::DerivedFrom => "derived_from",
            Self::FlowsTo => "flows_to",
            Self::GuardedBy => "guarded_by",
            Self::SanitizedBy => "sanitized_by",
            Self::Contradicts => "contradicts",
            Self::ReportedAs => "reported_as",
        }
    }
}

impl TryFrom<&str> for StaticEvidenceEdgeKind {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value.trim() {
            "supports" => Ok(Self::Supports),
            "derived_from" | "derived-from" => Ok(Self::DerivedFrom),
            "flows_to" | "flows-to" => Ok(Self::FlowsTo),
            "guarded_by" | "guarded-by" => Ok(Self::GuardedBy),
            "sanitized_by" | "sanitized-by" => Ok(Self::SanitizedBy),
            "contradicts" => Ok(Self::Contradicts),
            "reported_as" | "reported-as" => Ok(Self::ReportedAs),
            other => anyhow::bail!("unknown static evidence edge kind {other:?}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StaticEvidenceNode {
    pub id: String,
    pub kind: StaticEvidenceNodeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    pub content_hash: String,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub metadata: Value,
    pub indexed_at_unix: u64,
}

impl StaticEvidenceNode {
    pub fn new(
        kind: StaticEvidenceNodeKind,
        title: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        let body = body.into();
        let mut node = Self {
            id: String::new(),
            kind,
            finding_fingerprint: None,
            source_path: None,
            start_line: None,
            end_line: None,
            content_hash: static_content_hash(&body),
            title: title.into(),
            body,
            metadata: Value::Object(Default::default()),
            indexed_at_unix: now_unix(),
        };
        node.refresh_id();
        node
    }

    pub fn with_finding_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.finding_fingerprint = Some(fingerprint.into());
        self.refresh_id();
        self
    }

    pub fn with_source_span(
        mut self,
        source_path: impl Into<String>,
        start_line: u32,
        end_line: Option<u32>,
    ) -> Self {
        self.source_path = Some(source_path.into());
        self.start_line = Some(start_line);
        self.end_line = end_line;
        self.refresh_id();
        self
    }

    pub fn with_metadata(mut self, metadata: Value) -> Self {
        self.metadata = metadata;
        self.refresh_id();
        self
    }

    pub fn stable_id(&self) -> String {
        evidence_node_id(self)
    }

    fn refresh_id(&mut self) {
        self.content_hash = static_content_hash(&self.body);
        self.id = self.stable_id();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StaticEvidenceEdge {
    pub id: String,
    pub kind: StaticEvidenceEdgeKind,
    pub from_node_id: String,
    pub to_node_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_fingerprint: Option<String>,
    #[serde(default)]
    pub metadata: Value,
    pub created_at_unix: u64,
}

impl StaticEvidenceEdge {
    pub fn new(
        kind: StaticEvidenceEdgeKind,
        from_node_id: impl Into<String>,
        to_node_id: impl Into<String>,
    ) -> Self {
        let mut edge = Self {
            id: String::new(),
            kind,
            from_node_id: from_node_id.into(),
            to_node_id: to_node_id.into(),
            finding_fingerprint: None,
            metadata: Value::Object(Default::default()),
            created_at_unix: now_unix(),
        };
        edge.refresh_id();
        edge
    }

    pub fn with_finding_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.finding_fingerprint = Some(fingerprint.into());
        self.refresh_id();
        self
    }

    pub fn with_metadata(mut self, metadata: Value) -> Self {
        self.metadata = metadata;
        self.refresh_id();
        self
    }

    pub fn stable_id(&self) -> String {
        evidence_edge_id(self)
    }

    fn refresh_id(&mut self) {
        self.id = self.stable_id();
    }
}

pub fn static_evidence_path(workspace: &WorkspaceTarget) -> PathBuf {
    workspace.state_dir().join(STATIC_EVIDENCE_DB_NAME)
}

pub struct StaticEvidenceStore {
    conn: Connection,
    db_path: String,
}

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

fn validate_node(node: &StaticEvidenceNode) -> Result<()> {
    if node.id.trim().is_empty() {
        anyhow::bail!("static evidence node id cannot be empty");
    }
    if node.id != node.stable_id() {
        anyhow::bail!(
            "static evidence node id {} does not match stable hash {}",
            node.id,
            node.stable_id()
        );
    }
    let expected_hash = static_content_hash(&node.body);
    if node.content_hash != expected_hash {
        anyhow::bail!(
            "static evidence node {} content hash does not match body hash",
            node.id
        );
    }
    if let Some(start_line) = node.start_line {
        if start_line == 0 {
            anyhow::bail!("static evidence node {} start_line must be >= 1", node.id);
        }
    }
    if let (Some(start_line), Some(end_line)) = (node.start_line, node.end_line) {
        if end_line < start_line {
            anyhow::bail!(
                "static evidence node {} end_line must be >= start_line",
                node.id
            );
        }
    }
    Ok(())
}

fn validate_edge(edge: &StaticEvidenceEdge) -> Result<()> {
    if edge.from_node_id.trim().is_empty() || edge.to_node_id.trim().is_empty() {
        anyhow::bail!("static evidence edge endpoints cannot be empty");
    }
    if edge.id != edge.stable_id() {
        anyhow::bail!(
            "static evidence edge id {} does not match stable hash {}",
            edge.id,
            edge.stable_id()
        );
    }
    Ok(())
}

fn row_to_node(row: &rusqlite::Row<'_>) -> rusqlite::Result<StaticEvidenceNode> {
    let raw_kind: String = row.get(1)?;
    let metadata_json: String = row.get(9)?;
    let metadata = serde_json::from_str::<Value>(&metadata_json).map_err(to_sql_error)?;
    let start_line = optional_u32(row.get::<_, Option<i64>>(4)?, "start_line")?;
    let end_line = optional_u32(row.get::<_, Option<i64>>(5)?, "end_line")?;
    Ok(StaticEvidenceNode {
        id: row.get(0)?,
        kind: StaticEvidenceNodeKind::try_from(raw_kind.as_str()).map_err(to_sql_anyhow_error)?,
        finding_fingerprint: row.get(2)?,
        source_path: row.get(3)?,
        start_line,
        end_line,
        content_hash: row.get(6)?,
        title: row.get(7)?,
        body: row.get(8)?,
        metadata,
        indexed_at_unix: row.get::<_, i64>(10)? as u64,
    })
}

fn row_to_edge(row: &rusqlite::Row<'_>) -> rusqlite::Result<StaticEvidenceEdge> {
    let raw_kind: String = row.get(1)?;
    let metadata_json: String = row.get(5)?;
    let metadata = serde_json::from_str::<Value>(&metadata_json).map_err(to_sql_error)?;
    Ok(StaticEvidenceEdge {
        id: row.get(0)?,
        kind: StaticEvidenceEdgeKind::try_from(raw_kind.as_str()).map_err(to_sql_anyhow_error)?,
        from_node_id: row.get(2)?,
        to_node_id: row.get(3)?,
        finding_fingerprint: row.get(4)?,
        metadata,
        created_at_unix: row.get::<_, i64>(6)? as u64,
    })
}

fn optional_u32(value: Option<i64>, name: &'static str) -> rusqlite::Result<Option<u32>> {
    match value {
        Some(value) if value < 0 || value > i64::from(u32::MAX) => Err(to_sql_anyhow_error(
            anyhow::anyhow!("static evidence {name} value {value} is out of range"),
        )),
        Some(value) => Ok(Some(value as u32)),
        None => Ok(None),
    }
}

fn evidence_node_id(node: &StaticEvidenceNode) -> String {
    let metadata_json = serde_json::to_string(&node.metadata).unwrap_or_else(|_| "{}".to_string());
    let hash = stable_hash_segments(&[
        "node",
        node.kind.as_str(),
        node.finding_fingerprint.as_deref().unwrap_or(""),
        node.source_path.as_deref().unwrap_or(""),
        &node
            .start_line
            .map(|line| line.to_string())
            .unwrap_or_default(),
        &node
            .end_line
            .map(|line| line.to_string())
            .unwrap_or_default(),
        &node.content_hash,
        &node.title,
        &metadata_json,
    ]);
    format!("SEV-N-{}", &hash[..16])
}

fn evidence_edge_id(edge: &StaticEvidenceEdge) -> String {
    let metadata_json = serde_json::to_string(&edge.metadata).unwrap_or_else(|_| "{}".to_string());
    let hash = stable_hash_segments(&[
        "edge",
        edge.kind.as_str(),
        &edge.from_node_id,
        &edge.to_node_id,
        edge.finding_fingerprint.as_deref().unwrap_or(""),
        &metadata_json,
    ]);
    format!("SEV-E-{}", &hash[..16])
}

pub fn static_content_hash(body: &str) -> String {
    fnv1a_hex(body.as_bytes())
}

fn stable_hash_segments(segments: &[&str]) -> String {
    let mut bytes = Vec::new();
    for segment in segments {
        bytes.extend_from_slice(segment.as_bytes());
        bytes.push(0);
    }
    fnv1a_hex(&bytes)
}

fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn to_sql_error(error: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
}

fn to_sql_anyhow_error(error: anyhow::Error) -> rusqlite::Error {
    let error = io::Error::new(io::ErrorKind::InvalidData, error.to_string());
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn static_evidence_kind_names_match_whitebox_spec() {
        let node_names = STATIC_EVIDENCE_NODE_KINDS
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            node_names,
            vec![
                "code_span",
                "scanner_signal",
                "source",
                "sink",
                "dataflow_step",
                "sanitizer",
                "guard",
                "attack_surface",
                "triage_claim",
                "report_claim",
            ]
        );
        for name in node_names {
            assert_eq!(
                StaticEvidenceNodeKind::try_from(name).unwrap().as_str(),
                name
            );
        }

        let edge_names = STATIC_EVIDENCE_EDGE_KINDS
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            edge_names,
            vec![
                "supports",
                "derived_from",
                "flows_to",
                "guarded_by",
                "sanitized_by",
                "contradicts",
                "reported_as",
            ]
        );
        for name in edge_names {
            assert_eq!(
                StaticEvidenceEdgeKind::try_from(name).unwrap().as_str(),
                name
            );
        }
    }

    #[test]
    fn static_evidence_store_inserts_fetches_and_links_nodes() {
        let store = StaticEvidenceStore::open_in_memory().unwrap();
        let code_span = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::CodeSpan,
            "route handler span",
            "const name = req.query.name;",
        )
        .with_finding_fingerprint("finding-1")
        .with_source_span("src/routes.ts", 12, Some(12))
        .with_metadata(json!({"language": "typescript"}));
        let scanner_signal = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::ScannerSignal,
            "semgrep express xss",
            "express-xss flagged src/routes.ts:12",
        )
        .with_finding_fingerprint("finding-1")
        .with_metadata(json!({"tool": "semgrep", "ruleId": "express-xss"}));

        store.upsert_node(&code_span).unwrap();
        store.upsert_node(&scanner_signal).unwrap();

        let fetched_span = store.get_node(&code_span.id).unwrap().unwrap();
        assert_eq!(fetched_span, code_span);
        assert_eq!(
            fetched_span.content_hash,
            static_content_hash(&fetched_span.body)
        );
        assert_eq!(store.list_nodes_for_finding("finding-1").unwrap().len(), 2);

        let edge = StaticEvidenceEdge::new(
            StaticEvidenceEdgeKind::DerivedFrom,
            scanner_signal.id.clone(),
            code_span.id.clone(),
        )
        .with_finding_fingerprint("finding-1")
        .with_metadata(json!({"normalizer": "semgrep"}));
        store.upsert_edge(&edge).unwrap();

        assert_eq!(store.get_edge(&edge.id).unwrap().unwrap(), edge);
        assert_eq!(store.edges_for_node(&code_span.id).unwrap(), vec![edge]);
    }

    #[test]
    fn static_evidence_hashes_are_stable_and_body_sensitive() {
        let first = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::Source,
            "request source",
            "req.query.name",
        )
        .with_finding_fingerprint("finding-2")
        .with_source_span("src/routes.ts", 8, Some(8))
        .with_metadata(json!({"framework": "express"}));
        let same = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::Source,
            "request source",
            "req.query.name",
        )
        .with_finding_fingerprint("finding-2")
        .with_source_span("src/routes.ts", 8, Some(8))
        .with_metadata(json!({"framework": "express"}));
        let changed_body = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::Source,
            "request source",
            "req.body.name",
        )
        .with_finding_fingerprint("finding-2")
        .with_source_span("src/routes.ts", 8, Some(8))
        .with_metadata(json!({"framework": "express"}));

        assert_eq!(first.id, same.id);
        assert_eq!(first.content_hash, same.content_hash);
        assert_ne!(first.id, changed_body.id);
        assert_ne!(first.content_hash, changed_body.content_hash);

        let first_edge =
            StaticEvidenceEdge::new(StaticEvidenceEdgeKind::FlowsTo, first.id.clone(), "sink-1")
                .with_finding_fingerprint("finding-2");
        let same_edge =
            StaticEvidenceEdge::new(StaticEvidenceEdgeKind::FlowsTo, first.id.clone(), "sink-1")
                .with_finding_fingerprint("finding-2");
        let changed_edge = StaticEvidenceEdge::new(
            StaticEvidenceEdgeKind::GuardedBy,
            first.id.clone(),
            "sink-1",
        )
        .with_finding_fingerprint("finding-2");

        assert_eq!(first_edge.id, same_edge.id);
        assert_ne!(first_edge.id, changed_edge.id);
    }

    #[test]
    fn static_evidence_store_uses_workspace_v2_path() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = StaticEvidenceStore::open(&workspace).unwrap();

        assert!(store
            .db_path()
            .ends_with(".kuzushi/v2/static-evidence.sqlite3"));
        assert!(static_evidence_path(&workspace).exists());
    }

    #[test]
    fn static_evidence_store_rejects_unhashed_or_mutated_source_evidence() {
        let store = StaticEvidenceStore::open_in_memory().unwrap();
        let mut node = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::CodeSpan,
            "route handler span",
            "const name = req.query.name;",
        );
        node.body = "const name = req.body.name;".to_string();

        let error = store.upsert_node(&node).unwrap_err().to_string();

        assert!(error.contains("content hash does not match body hash"));
    }
}
