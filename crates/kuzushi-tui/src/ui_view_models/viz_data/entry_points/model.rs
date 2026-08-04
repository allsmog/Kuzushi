#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EntryPointBreakdown {
    pub entries: Vec<EntryPointItem>,
    pub kinds: Vec<EntryPointGroup>,
    pub zones: Vec<EntryPointGroup>,
    pub dispositions: Vec<EntryPointGroup>,
    pub counts: EntryPointCounts,
    pub receipt: EntryPointReceipt,
    pub linked_target_count: usize,
    pub target_count: usize,
    pub empty_hint: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EntryPointCounts {
    pub extracted: usize,
    pub modeled: usize,
    pub overlap: usize,
    pub deprioritized: usize,
    pub unrepresented: usize,
    pub model_only: usize,
    pub union: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EntryPointReceipt {
    pub catalog_artifact: EntryPointArtifactStatus,
    pub model_artifact: EntryPointArtifactStatus,
    pub composition: EntryPointComposition,
    pub freshness: EntryPointFreshness,
    pub catalog_status: Option<String>,
    pub catalog_digest: Option<String>,
    pub model_catalog_digest: Option<String>,
    pub context_digest: Option<String>,
    pub model_context_digest: Option<String>,
    pub tree_hash: Option<String>,
    pub model_tree_hash: Option<String>,
    pub catalog_timestamp_ms: Option<u64>,
    pub snapshot_timestamp_ms: Option<u64>,
    pub model_built_at_ms: Option<u64>,
    pub revision: Option<String>,
    pub revision_dirty: Option<bool>,
    pub records: Option<usize>,
    pub records_selected: Option<usize>,
    pub grounding_limit: Option<usize>,
    pub grounding_records_selected: Option<usize>,
    pub records_linked: Option<usize>,
    pub selection_policy: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum EntryPointArtifactStatus {
    Ready,
    #[default]
    Missing,
    Loading,
    Malformed,
    NonFile,
    Unreadable,
}

impl EntryPointArtifactStatus {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Missing => "missing",
            Self::Loading => "loading",
            Self::Malformed => "malformed",
            Self::NonFile => "not a file",
            Self::Unreadable => "unreadable",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum EntryPointComposition {
    Current,
    ChangedSinceModel,
    ProvenanceUnknown,
    CatalogOnly,
    ModelOnly,
    #[default]
    Unavailable,
}

impl EntryPointComposition {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Current => "catalog matches model receipt",
            Self::ChangedSinceModel => "catalog changed since model",
            Self::ProvenanceUnknown => "provenance unknown",
            Self::CatalogOnly => "extractor catalog only",
            Self::ModelOnly => "threat model only",
            Self::Unavailable => "composition unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum EntryPointFreshness {
    Current,
    Stale,
    #[default]
    Unknown,
}

impl EntryPointFreshness {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Current => "evidence current",
            Self::Stale => "evidence stale",
            Self::Unknown => "freshness unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EntryPointGroup {
    pub name: String,
    pub count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum EntryPointDisposition {
    Modeled,
    Deprioritized,
    ExtractedOnly,
    ModelOnly,
}

impl EntryPointDisposition {
    pub(super) const ALL: [Self; 4] = [
        Self::Modeled,
        Self::Deprioritized,
        Self::ExtractedOnly,
        Self::ModelOnly,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Modeled => "modeled",
            Self::Deprioritized => "deprioritized",
            Self::ExtractedOnly => "extracted only",
            Self::ModelOnly => "model only",
        }
    }

    pub(super) fn rank(self) -> usize {
        match self {
            Self::Modeled => 0,
            Self::Deprioritized => 1,
            Self::ExtractedOnly => 2,
            Self::ModelOnly => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EntryPointItem {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub trust_zone: String,
    pub description: String,
    pub ingress: String,
    pub source: String,
    pub evidence: String,
    pub risk: String,
    pub disposition: EntryPointDisposition,
    pub disposition_note: String,
    pub targets: Vec<EntryPointTarget>,
    pub unresolved_target_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EntryPointTarget {
    pub id: String,
    pub label: String,
}
