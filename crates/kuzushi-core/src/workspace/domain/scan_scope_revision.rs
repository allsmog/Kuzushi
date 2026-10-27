use super::{ScanScopeCoverage, ScanScopeDraft, ScopeCoverageApproval};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanScopeSource {
    pub snapshot_hash: String,
    pub tree_hash: String,
    pub git_revision: Option<String>,
    pub dirty: Option<bool>,
    /// Binds the enumerated membership separately from working-tree contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enumeration_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanScopeProposalRef {
    pub proposal_id: String,
    pub revision: u32,
    pub record_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanScopeRevision {
    pub schema_version: u32,
    pub proposal_id: String,
    pub revision: u32,
    pub previous: Option<ScanScopeProposalRef>,
    pub source: ScanScopeSource,
    pub inventory_hash: String,
    pub draft: ScanScopeDraft,
    /// Acceptance approves these boundaries only, never scan jobs or spending.
    pub acceptance: Option<ScopeCoverageApproval>,
    /// The exact model input receipt survives edits; acceptance is always separate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<ScanScopeGeneration>,
    /// Manual correction of authenticated rejected output, never a model verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correction: Option<super::ScanScopeCorrection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanScopeGeneration {
    pub schema_version: u32,
    pub model: String,
    pub run_id: String,
    pub prompt_sha256: String,
    pub draft_sha256: String,
    pub context_ref: Option<crate::ThreatModelRef>,
    pub input_bytes: usize,
    pub supplied_files: usize,
    pub inventoried_files: usize,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanScopeReview {
    pub reference: ScanScopeProposalRef,
    pub record: ScanScopeRevision,
    pub coverage: ScanScopeCoverage,
    pub identity_omissions: super::ScopeFilePreview,
}
