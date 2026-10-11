use super::*;
use crate::workspace::ScanScopeRef;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgenticScopeReceipt {
    pub reference: ScanScopeRef,
    pub name: String,
    pub discovery_files: usize,
    pub inherited_context_files: usize,
    pub read_membership_sha256: String,
}
