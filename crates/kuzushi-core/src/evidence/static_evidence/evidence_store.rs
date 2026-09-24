use super::*;

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

    pub(crate) fn refresh_id(&mut self) {
        self.id = self.stable_id();
    }
}

pub fn static_evidence_path(workspace: &WorkspaceTarget) -> PathBuf {
    crate::workspace::workspace_static_evidence_db_path(workspace.root())
}

pub struct StaticEvidenceStore {
    pub(crate) conn: Connection,
    pub(crate) db_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StaticEvidenceIndexReport {
    pub db_path: String,
    pub findings_indexed: usize,
    pub nodes_indexed: usize,
    pub edges_indexed: usize,
    pub node_ids: Vec<String>,
    pub edge_ids: Vec<String>,
    /// Source results the indexer could not ground in a physical location.
    /// The scan engine discloses the same omission in its `scan_errors`; the
    /// count rides here so the index receipt never reads as a complete copy.
    #[serde(default, skip_serializing_if = "is_zero_count")]
    pub results_omitted: usize,
}

fn is_zero_count(value: &usize) -> bool {
    *value == 0
}

impl StaticEvidenceIndexReport {
    pub(crate) fn new(db_path: impl Into<String>) -> Self {
        Self {
            db_path: db_path.into(),
            findings_indexed: 0,
            nodes_indexed: 0,
            edges_indexed: 0,
            node_ids: Vec::new(),
            edge_ids: Vec::new(),
            results_omitted: 0,
        }
    }
}
