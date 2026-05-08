use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
pub(crate) struct MatchReport {
    pub(crate) slice: String,
    pub(crate) oracle_cve: String,
    pub(crate) oracle_name: Option<String>,
    pub(crate) oracle_commit: Option<String>,
    pub(crate) findings_total: usize,
    pub(crate) hits: usize,
    pub(crate) misses: usize,
    pub(crate) near_misses: usize,
    pub(crate) precision: f64,
    pub(crate) recall: RecallByTolerance,
    pub(crate) proof_state_breakdown: ProofStateBreakdown,
    pub(crate) vuln_source_breakdown: BTreeMap<String, usize>,
    pub(crate) matches: Vec<MatchRow>,
    pub(crate) missed_oracle: Vec<MissedOracle>,
    pub(crate) expected_min_recall: f64,
    pub(crate) cost_usd: f64,
    pub(crate) wall_seconds: u64,
}

#[derive(Debug, Serialize, Default)]
pub(crate) struct RecallByTolerance {
    pub(crate) exact_line: f64,
    pub(crate) pm_lines: f64,
    #[serde(rename = "function")]
    pub(crate) function_: f64,
    pub(crate) file_only: f64,
}

#[derive(Debug, Serialize)]
pub(crate) struct MatchRow {
    pub(crate) oracle_idx: usize,
    pub(crate) finding_fingerprint: String,
    pub(crate) finding_rule_id: String,
    pub(crate) finding_tool: String,
    pub(crate) file: String,
    pub(crate) finding_line: u32,
    pub(crate) oracle_line: u32,
    pub(crate) delta: i64,
    pub(crate) best_tolerance: String,
    pub(crate) cwe_match: bool,
    pub(crate) finding_cwes: Vec<String>,
    pub(crate) oracle_cwes: Vec<String>,
    pub(crate) vuln_source: Option<String>,
    pub(crate) static_proof_state: Option<String>,
}

#[derive(Debug, Serialize, Default)]
pub(crate) struct ProofStateBreakdown {
    pub(crate) validated: usize,
    pub(crate) other_static: usize,
    pub(crate) llm_only: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct MissedOracle {
    pub(crate) idx: usize,
    pub(crate) file: String,
    pub(crate) function: String,
    pub(crate) line_start: u32,
    pub(crate) cwe: Vec<String>,
}
