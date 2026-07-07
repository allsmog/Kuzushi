use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintCweSelection {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisReport {
    pub(crate) target: String,
    pub(crate) count: usize,
    pub(crate) cwes: Vec<TaintCweSelection>,
    pub(crate) findings: Vec<Finding>,
    /// Structured source→sink flows (parallel to `findings`), preserved for the
    /// TUI attack-path visualization since `findings` flatten the path to text.
    pub(crate) flows: Vec<TaintFlow>,
    pub(crate) persisted: Option<TaintIrisPersistedRun>,
    pub(crate) cost_usd: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) degradation: Option<Value>,
}

/// One taint flow: the CWE/severity plus its ordered source→sink stages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintFlow {
    pub(crate) cwe: String,
    pub(crate) severity: String,
    pub(crate) stages: Vec<TaintFlowStage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintFlowStage {
    pub(crate) message: String,
    pub(crate) file_path: String,
    pub(crate) line: u32,
    pub(crate) snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisPersistedRun {
    pub(crate) run_id: String,
    pub(crate) findings_db: String,
}
