use super::scan_scope_revision::{ScanScopeProposalRef, ScanScopeSource};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanScopeRef {
    pub proposal: ScanScopeProposalRef,
    pub scope_id: String,
}

/// Resolved source membership, separate from bounded coverage previews.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptedScanScopeSelection {
    pub reference: ScanScopeRef,
    pub name: String,
    pub source: ScanScopeSource,
    pub discovery_files: Vec<String>,
    pub context_files: Vec<String>,
}
