use serde::Deserialize;

use crate::findings::{GroundingStatus, Severity, StaticProofState, VulnSource};

/// The structural leakage firewall.
///
/// This is the only view the feature extractor ever has of a finding snapshot.
/// `$.triage`, `$.triaged_by`, `$.suppressed`, `$.snoozed_until`,
/// `$.verification`, `$.message`, `$.title`, `$.fingerprint`, `$.identityId`
/// and every evidence snippet, rationale, or HTTP blob are simply not fields
/// here, so no future edit to the extractor can read one by accident.
///
/// `deny_unknown_fields` is deliberately absent: stored snapshots do carry the
/// forbidden keys, and rejecting them would break the export instead of
/// ignoring them.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct AnchorSnapshotView {
    pub severity: Severity,
    #[serde(rename = "staticProofState", alias = "static_proof_state", default)]
    pub static_proof_state: Option<StaticProofState>,
    #[serde(default)]
    pub vuln_source: Option<VulnSource>,
    #[serde(default)]
    pub tool: String,
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub category: Option<String>,
    /// Consumed only to derive `path_bucket` and `language_family`; the path
    /// itself never reaches a feature or a row.
    #[serde(default)]
    pub file_path: String,
    #[serde(rename = "identityMatchTier", alias = "identity_match_tier", default)]
    pub identity_match_tier: Option<String>,
    #[serde(default)]
    pub grounding: Option<GroundingStatus>,
    #[serde(default)]
    pub exploit_scenario: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub preconditions: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<EvidenceView>,
    /// Only the length is ever read.
    #[serde(default)]
    pub sources: Vec<serde_json::Value>,
    #[serde(default)]
    pub corroboration_count: u32,
}

/// Evidence reduced to its shape: a kind and a confidence. Snippets,
/// rationales, file paths, and request/response blobs are unreadable.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct EvidenceView {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub confidence: u8,
}
