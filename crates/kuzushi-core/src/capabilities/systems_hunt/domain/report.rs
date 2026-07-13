use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsHuntReport {
    pub target: String,
    pub count: usize,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted: Option<SystemsHuntPersistedRun>,
    pub artifacts: Vec<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsHuntPersistedRun {
    pub run_id: String,
    pub findings_db: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeepSemanticCweSelection {
    pub id: String,
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeepSemanticCweOutput {
    pub cwes: Vec<DeepSemanticCweSelection>,
    pub cost_usd: f64,
    pub cost_usd_exact: bool,
}
