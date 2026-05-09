use super::*;

#[derive(Debug, Clone)]
pub(crate) struct TaintIrisNextAgentResult {
    pub(crate) agent_status: String,
    pub(crate) selected_cwes: Vec<Value>,
    pub(crate) findings: Vec<Finding>,
    pub(crate) review_candidates: Vec<Finding>,
    pub(crate) triage: Vec<Value>,
    pub(crate) triage_summary: Value,
    pub(crate) outcome: String,
    pub(crate) raw_output: Value,
    pub(crate) structured_output_valid: bool,
    pub(crate) structured_output_retry_count: usize,
    pub(crate) parse_error: Option<String>,
    pub(crate) result_text_excerpt: Option<String>,
    pub(crate) warnings: Vec<String>,
    pub(crate) cost_usd: f64,
}

pub(crate) const TAINT_IRIS_NEXT_ANY: &[&str] = &["any"];

pub(crate) const TAINT_IRIS_NEXT_WEB: &[&str] = &[
    "javascript",
    "typescript",
    "python",
    "ruby",
    "php",
    "java",
    "go",
    "csharp",
];

pub(crate) const TAINT_IRIS_NEXT_NATIVE: &[&str] = &["c", "cpp", "go", "rust"];
