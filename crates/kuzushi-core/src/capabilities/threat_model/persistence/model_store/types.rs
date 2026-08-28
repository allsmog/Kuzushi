use super::*;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ThreatModelId(String);

impl ThreatModelId {
    pub fn new() -> Self {
        Self(format!("tm_{}", Uuid::new_v4().simple()))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_typed_id(&value, "tm_")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ThreatModelId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ThreatModelId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for ThreatModelId {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ThreatModelRevisionId(String);

impl ThreatModelRevisionId {
    pub fn new() -> Self {
        Self(format!("tmr_{}", Uuid::new_v4().simple()))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_typed_id(&value, "tmr_")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ThreatModelRevisionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ThreatModelRevisionId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for ThreatModelRevisionId {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreatModelRef {
    pub model_id: ThreatModelId,
    pub revision_id: ThreatModelRevisionId,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeRef {
    pub scope_id: String,
    pub rel_path: PathBuf,
    pub project_model_sha256: String,
    pub target_revision: String,
}

impl ScopeRef {
    pub fn legacy_root(root: &Path, document_sha256: &str) -> Self {
        let target_revision = crate::workspace::target_git_metadata(root)
            .map(|metadata| metadata.sha)
            .unwrap_or_else(|| "unavailable".to_string());
        Self {
            scope_id: "root".to_string(),
            rel_path: PathBuf::from("."),
            project_model_sha256: document_sha256.to_string(),
            target_revision,
        }
    }

    pub fn same_lineage_category(&self, other: &Self) -> bool {
        self.scope_id == other.scope_id
            && self.rel_path == other.rel_path
            && self.project_model_sha256 == other.project_model_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThreatModelRevisionSource {
    Build,
    Refine,
    Verify,
    Import,
    Restore,
    Adopt,
    OperatorEdit,
    LegacyImport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActivationSource {
    Build,
    Refine,
    Verify,
    Import,
    Restore,
    Adopt,
    OperatorEdit,
    Activate,
    DiscardForce,
    LegacyImport,
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreatModelVerificationCache {
    pub verdict: String,
    pub document_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreatModelRevisionMetadata {
    pub revision_id: ThreatModelRevisionId,
    pub sha256: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_revision_id: Option<ThreatModelRevisionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision_id: Option<ThreatModelRevisionId>,
    pub source: ThreatModelRevisionSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<ThreatModelVerificationCache>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreatModelMetadata {
    pub model_id: ThreatModelId,
    pub label: String,
    pub scope: ScopeRef,
    pub methodology: String,
    pub created_at: String,
    pub head_revision: ThreatModelRevisionId,
    pub revisions: Vec<ThreatModelRevisionMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreatModelActivation {
    pub event_id: String,
    pub manifest_generation: u64,
    pub activated_at: String,
    pub model_ref: ThreatModelRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<ThreatModelRef>,
    pub actor: String,
    pub source: ActivationSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discarded_mirror_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreatModelManifest {
    pub schema_version: u32,
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<ThreatModelRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_activation: Option<ThreatModelActivation>,
    #[serde(default)]
    pub models: Vec<ThreatModelMetadata>,
}

impl Default for ThreatModelManifest {
    fn default() -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION,
            generation: 0,
            active: None,
            last_activation: None,
            models: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ThreatModelCommit {
    pub model_id: Option<ThreatModelId>,
    pub new_model: bool,
    pub label: String,
    pub scope: ScopeRef,
    pub methodology: String,
    pub source: ThreatModelRevisionSource,
    pub source_revision_id: Option<ThreatModelRevisionId>,
    pub run_id: Option<String>,
    pub activate: Option<bool>,
    pub actor: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatModelCommitResult {
    pub model_ref: ThreatModelRef,
    pub activated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorAction {
    Refuse,
    Discard,
}

#[derive(Debug, thiserror::Error)]
pub enum ThreatModelStoreError {
    #[error(
        "compatibility mirror diverged from active threat model (mirror {mirror_sha256}, active {active_sha256}); next: adopt edits, inspect diff, or discard --force"
    )]
    DivergentMirror {
        mirror_sha256: String,
        active_sha256: String,
    },
    #[error(
        "compatibility mirror cannot be adopted ({reason}; mirror {mirror_sha256}, active {active_sha256}); next: inspect the file or discard --force"
    )]
    UnadoptableMirror {
        mirror_sha256: String,
        active_sha256: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActiveThreatModel {
    pub model_ref: ThreatModelRef,
    pub document: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreatModelJsonChange {
    pub pointer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mirror: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreatModelMirrorDiff {
    pub active: ThreatModelRef,
    pub mirror_sha256: String,
    pub changes: Vec<ThreatModelJsonChange>,
    pub truncated: bool,
}
