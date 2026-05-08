use super::*;

impl StaticEvidenceEdgeKind {
    pub fn as_str(self) -> &'static str {
        STATIC_EVIDENCE_EDGE_KIND_LABELS
            .iter()
            .find_map(|(kind, label)| (*kind == self).then_some(*label))
            .unwrap_or("supports")
    }
}

impl TryFrom<&str> for StaticEvidenceEdgeKind {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        let normalized = value.trim();
        STATIC_EVIDENCE_EDGE_KIND_ALIASES
            .iter()
            .find_map(|(alias, kind)| (*alias == normalized).then_some(*kind))
            .with_context(|| format!("unknown static evidence edge kind {normalized:?}"))
    }
}

const STATIC_EVIDENCE_EDGE_KIND_LABELS: &[(StaticEvidenceEdgeKind, &str)] = &[
    (StaticEvidenceEdgeKind::Supports, "supports"),
    (StaticEvidenceEdgeKind::DerivedFrom, "derived_from"),
    (StaticEvidenceEdgeKind::FlowsTo, "flows_to"),
    (StaticEvidenceEdgeKind::GuardedBy, "guarded_by"),
    (StaticEvidenceEdgeKind::SanitizedBy, "sanitized_by"),
    (StaticEvidenceEdgeKind::Contradicts, "contradicts"),
    (StaticEvidenceEdgeKind::ReportedAs, "reported_as"),
];

const STATIC_EVIDENCE_EDGE_KIND_ALIASES: &[(&str, StaticEvidenceEdgeKind)] = &[
    ("supports", StaticEvidenceEdgeKind::Supports),
    ("derived_from", StaticEvidenceEdgeKind::DerivedFrom),
    ("derived-from", StaticEvidenceEdgeKind::DerivedFrom),
    ("flows_to", StaticEvidenceEdgeKind::FlowsTo),
    ("flows-to", StaticEvidenceEdgeKind::FlowsTo),
    ("guarded_by", StaticEvidenceEdgeKind::GuardedBy),
    ("guarded-by", StaticEvidenceEdgeKind::GuardedBy),
    ("sanitized_by", StaticEvidenceEdgeKind::SanitizedBy),
    ("sanitized-by", StaticEvidenceEdgeKind::SanitizedBy),
    ("contradicts", StaticEvidenceEdgeKind::Contradicts),
    ("reported_as", StaticEvidenceEdgeKind::ReportedAs),
    ("reported-as", StaticEvidenceEdgeKind::ReportedAs),
];

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

    pub(crate) fn refresh_id(&mut self) {
        self.content_hash = static_content_hash(&self.body);
        self.id = self.stable_id();
    }
}
