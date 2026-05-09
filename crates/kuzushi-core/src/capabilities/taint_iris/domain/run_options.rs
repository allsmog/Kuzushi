#[derive(Debug, Clone)]
pub(crate) struct TaintIrisInput {
    pub(crate) max_cwes: Option<usize>,
    pub(crate) max_findings: usize,
    pub(crate) prompt_override: Option<String>,
    pub(crate) max_budget_usd: Option<f64>,
}
