//! Source identity explicitly selected for a human decision, separate from observations.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewSourceCapture {
    pub schema_version: u32,
    pub target_identity: String,
    pub finding_id: i64,
    pub stable_fp: String,
    pub read_watermark: u64,
    pub snapshot_hash: String,
    pub tree_hash: String,
    pub source_git: Option<crate::RunTargetGitMetadata>,
    pub captured_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cited_file: Option<ReviewCapturedFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewCapturedFile {
    pub path: String,
    pub state: ReviewCapturedFileState,
    pub blob_hash: Option<crate::identity::Blake3Hash>,
    pub byte_count: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewCapturedFileState {
    Captured,
    ExcludedOrMissing,
    TooLarge,
    BinaryOrInvalidText,
}
