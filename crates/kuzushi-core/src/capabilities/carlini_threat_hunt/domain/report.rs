use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CarliniThreatHuntPersistedRun {
    pub run_id: String,
    pub findings_db: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CarliniThreatHuntReport {
    pub target: String,
    pub count: usize,
    pub actors: usize,
    pub actor_runs: usize,
    pub prompt_inventory_files: usize,
    pub threat_focused_prompt_files: usize,
    pub findings: Vec<Finding>,
    /// Model-reported findings the deterministic normalizer rejected.
    /// Disclosed, never silently dropped.
    #[serde(default)]
    pub rejected_count: usize,
    /// Bounded actor-scoped reasons; `rejected_count` remains authoritative.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejection_reasons: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted: Option<CarliniThreatHuntPersistedRun>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kb_context: Option<ArtifactKnowledgePromptContext>,
    /// Exact and incomplete cost envelopes use different JSON field names.
    /// Accept the canonical incomplete form when `sast:scan` rehydrates this
    /// report from a normalized subtool result.
    #[serde(alias = "observedCostUsd")]
    pub cost_usd: f64,
    #[serde(default = "default_cost_usd_exact", skip_serializing_if = "is_true")]
    pub cost_usd_exact: bool,
}

const fn default_cost_usd_exact() -> bool {
    true
}

const fn is_true(value: &bool) -> bool {
    *value
}
