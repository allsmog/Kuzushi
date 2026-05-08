use super::prelude::*;
use super::*;

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

pub(crate) fn main() -> Result<()> {
    let cli = Cli::parse();
    let report = load_match_report(&cli)?;
    println!("{}", render_match_report(&report, cli.pretty)?);
    Ok(())
}

pub(crate) fn load_match_report(cli: &Cli) -> Result<MatchReport> {
    let oracle: Oracle = serde_json::from_str(
        &fs::read_to_string(&cli.oracle)
            .with_context(|| format!("read oracle {}", cli.oracle.display()))?,
    )
    .with_context(|| format!("parse oracle {}", cli.oracle.display()))?;

    let findings: FindingsDump = serde_json::from_str(
        &fs::read_to_string(&cli.findings)
            .with_context(|| format!("read findings {}", cli.findings.display()))?,
    )
    .with_context(|| format!("parse findings {}", cli.findings.display()))?;

    let target = cli.target.canonicalize().unwrap_or(cli.target.clone());

    Ok(score(cli, &oracle, &findings, &target))
}

pub(crate) fn render_match_report(report: &MatchReport, pretty: bool) -> Result<String> {
    let output = if pretty {
        serde_json::to_string_pretty(&report)?
    } else {
        serde_json::to_string(&report)?
    };
    Ok(output)
}
