use serde::{Deserialize, Serialize};

/// The exact failed job and authenticated local output reviewed by an operator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RejectedScopeRef {
    pub schema_version: u32,
    pub campaign_id: String,
    pub plan_sha256: String,
    pub run_id: String,
    pub artifact_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanScopeCorrection {
    pub schema_version: u32,
    pub rejected: RejectedScopeRef,
    pub model: String,
    pub context_ref: Option<crate::ThreatModelRef>,
    pub corrected_draft_sha256: String,
}
