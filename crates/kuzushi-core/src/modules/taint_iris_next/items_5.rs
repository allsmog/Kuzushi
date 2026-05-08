use super::prelude::*;
use super::*;

#[derive(Debug, Clone)]
pub(in crate::modules) struct TaintIrisNextAgentResult {
    pub(in crate::modules) agent_status: String,
    pub(in crate::modules) selected_cwes: Vec<Value>,
    pub(in crate::modules) findings: Vec<Finding>,
    pub(in crate::modules) review_candidates: Vec<Finding>,
    pub(in crate::modules) triage: Vec<Value>,
    pub(in crate::modules) triage_summary: Value,
    pub(in crate::modules) outcome: String,
    pub(in crate::modules) raw_output: Value,
    pub(in crate::modules) structured_output_valid: bool,
    pub(in crate::modules) structured_output_retry_count: usize,
    pub(in crate::modules) parse_error: Option<String>,
    pub(in crate::modules) result_text_excerpt: Option<String>,
    pub(in crate::modules) warnings: Vec<String>,
    pub(in crate::modules) cost_usd: f64,
}

pub(in crate::modules) const TAINT_IRIS_NEXT_ANY: &[&str] = &["any"];

pub(in crate::modules) const TAINT_IRIS_NEXT_WEB: &[&str] = &[
    "javascript",
    "typescript",
    "python",
    "ruby",
    "php",
    "java",
    "go",
    "csharp",
];

pub(in crate::modules) const TAINT_IRIS_NEXT_NATIVE: &[&str] = &["c", "cpp", "go", "rust"];
