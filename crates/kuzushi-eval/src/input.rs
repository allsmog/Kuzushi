use serde::Deserialize;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct Oracle {
    pub(crate) cve: String,
    pub(crate) slice: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) commit: Option<String>,
    pub(crate) ground_truth: Vec<OracleEntry>,
    pub(crate) expected_min_recall: Option<f64>,
    pub(crate) notes: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct OracleEntry {
    pub(crate) file: String,
    #[serde(default)]
    pub(crate) function: String,
    #[serde(default)]
    pub(crate) line_start: u32,
    #[serde(default)]
    pub(crate) line_end: u32,
    #[serde(default)]
    pub(crate) cwe: Vec<String>,
    #[serde(default)]
    pub(crate) kind: String,
    #[serde(default)]
    pub(crate) notes: String,
    #[serde(default)]
    pub(crate) expected_verdict: Option<String>,
    #[serde(default)]
    pub(crate) expected_severity: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct FindingsDump {
    #[serde(default)]
    pub(crate) count: usize,
    pub(crate) findings: Vec<FindingRow>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct FindingRow {
    pub(crate) fingerprint: String,
    pub(crate) rule_id: String,
    #[serde(default)]
    pub(crate) title: String,
    pub(crate) severity: String,
    pub(crate) file_path: String,
    pub(crate) start_line: u32,
    #[serde(default)]
    pub(crate) end_line: Option<u32>,
    #[serde(default)]
    pub(crate) message: String,
    pub(crate) tool: String,
    #[serde(default, alias = "vulnSource")]
    pub(crate) vuln_source: Option<String>,
    #[serde(default, alias = "staticProofState")]
    pub(crate) static_proof_state: Option<String>,
    #[serde(default)]
    pub(crate) verdict: Option<String>,
    #[serde(default)]
    pub(crate) triage: Option<FindingTriageRow>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct FindingTriageRow {
    pub(crate) verdict: String,
}
