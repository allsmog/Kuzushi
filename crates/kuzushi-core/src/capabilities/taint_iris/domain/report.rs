use super::*;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintCweSelection {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisReport {
    pub(crate) target: String,
    pub(crate) count: usize,
    pub(crate) cwes: Vec<TaintCweSelection>,
    pub(crate) findings: Vec<Finding>,
    pub(crate) persisted: Option<TaintIrisPersistedRun>,
    pub(crate) cost_usd: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) degradation: Option<Value>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisPersistedRun {
    pub(crate) run_id: String,
    pub(crate) findings_db: String,
}
