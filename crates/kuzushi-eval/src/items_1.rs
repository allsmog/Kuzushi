use super::prelude::*;
use super::*;

pub(crate) const PM_LINES_PRIMARY: i64 = 10;

pub(crate) const PM_LINES_FUNCTION_FALLBACK: i64 = 50;

#[derive(Debug, Parser)]
#[command(
    name = "kuzushi-eval",
    about = "Score Kuzushi findings against an oracle"
)]
pub(crate) struct Cli {
    /// Oracle JSON file (e.g. experiments/xint-eval/oracles/linux-cve-2026-31431.json).
    #[arg(long)]
    pub(crate) oracle: PathBuf,

    /// Findings JSON dump from `kuzushi findings --target <slice> --json`.
    #[arg(long)]
    pub(crate) findings: PathBuf,

    /// Slice name (e.g. "linux"). Used in the output for grouping.
    #[arg(long)]
    pub(crate) slice: String,

    /// Slice root directory; used to normalise file paths to repo-relative.
    #[arg(long)]
    pub(crate) target: PathBuf,

    /// Wall-clock seconds spent on the scan that produced the findings.
    #[arg(long, default_value_t = 0)]
    pub(crate) wall_seconds: u64,

    /// Pretty-print the output JSON.
    #[arg(long, default_value_t = true)]
    pub(crate) pretty: bool,
}

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
}
