// kuzushi-eval — recall scorer for the xint-eval harness.
//
// Reads an oracle JSON (ground-truth bug locations) and a findings JSON dump
// (`kuzushi findings --target … --json`), and emits a match report under four
// tolerance modes simultaneously: exact_line, pm_lines, function, file_only.
//
// Phase 0 ships without tree-sitter, so the `function` tolerance falls back to
// pm_lines:50. Phase 5 will rewire it to the real enclosing-function lookup.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};

const PM_LINES_PRIMARY: i64 = 10;
const PM_LINES_FUNCTION_FALLBACK: i64 = 50;

#[derive(Debug, Parser)]
#[command(
    name = "kuzushi-eval",
    about = "Score Kuzushi findings against an oracle"
)]
struct Cli {
    /// Oracle JSON file (e.g. experiments/xint-eval/oracles/linux-cve-2026-31431.json).
    #[arg(long)]
    oracle: PathBuf,

    /// Findings JSON dump from `kuzushi findings --target <slice> --json`.
    #[arg(long)]
    findings: PathBuf,

    /// Slice name (e.g. "linux"). Used in the output for grouping.
    #[arg(long)]
    slice: String,

    /// Slice root directory; used to normalise file paths to repo-relative.
    #[arg(long)]
    target: PathBuf,

    /// Wall-clock seconds spent on the scan that produced the findings.
    #[arg(long, default_value_t = 0)]
    wall_seconds: u64,

    /// Pretty-print the output JSON.
    #[arg(long, default_value_t = true)]
    pretty: bool,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Oracle {
    cve: String,
    slice: Option<String>,
    name: Option<String>,
    commit: Option<String>,
    ground_truth: Vec<OracleEntry>,
    expected_min_recall: Option<f64>,
    notes: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
struct OracleEntry {
    file: String,
    #[serde(default)]
    function: String,
    #[serde(default)]
    line_start: u32,
    #[serde(default)]
    line_end: u32,
    #[serde(default)]
    cwe: Vec<String>,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    notes: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct FindingsDump {
    #[serde(default)]
    count: usize,
    findings: Vec<FindingRow>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct FindingRow {
    fingerprint: String,
    rule_id: String,
    #[serde(default)]
    title: String,
    severity: String,
    file_path: String,
    start_line: u32,
    #[serde(default)]
    end_line: Option<u32>,
    #[serde(default)]
    message: String,
    tool: String,
    #[serde(default, alias = "vulnSource")]
    vuln_source: Option<String>,
    #[serde(default, alias = "staticProofState")]
    static_proof_state: Option<String>,
}

#[derive(Debug, Serialize)]
struct MatchReport {
    slice: String,
    oracle_cve: String,
    oracle_name: Option<String>,
    oracle_commit: Option<String>,
    findings_total: usize,
    hits: usize,
    misses: usize,
    near_misses: usize,
    precision: f64,
    recall: RecallByTolerance,
    proof_state_breakdown: ProofStateBreakdown,
    vuln_source_breakdown: BTreeMap<String, usize>,
    matches: Vec<MatchRow>,
    missed_oracle: Vec<MissedOracle>,
    expected_min_recall: f64,
    cost_usd: f64,
    wall_seconds: u64,
}

#[derive(Debug, Serialize, Default)]
struct RecallByTolerance {
    exact_line: f64,
    pm_lines: f64,
    #[serde(rename = "function")]
    function_: f64,
    file_only: f64,
}

#[derive(Debug, Serialize)]
struct MatchRow {
    oracle_idx: usize,
    finding_fingerprint: String,
    finding_rule_id: String,
    finding_tool: String,
    file: String,
    finding_line: u32,
    oracle_line: u32,
    delta: i64,
    best_tolerance: String,
    cwe_match: bool,
    finding_cwes: Vec<String>,
    oracle_cwes: Vec<String>,
    vuln_source: Option<String>,
    static_proof_state: Option<String>,
}

#[derive(Debug, Serialize, Default)]
struct ProofStateBreakdown {
    validated: usize,
    other_static: usize,
    llm_only: usize,
}

#[derive(Debug, Serialize)]
struct MissedOracle {
    idx: usize,
    file: String,
    function: String,
    line_start: u32,
    cwe: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let report = load_match_report(&cli)?;
    println!("{}", render_match_report(&report, cli.pretty)?);
    Ok(())
}

fn load_match_report(cli: &Cli) -> Result<MatchReport> {
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

fn render_match_report(report: &MatchReport, pretty: bool) -> Result<String> {
    let output = if pretty {
        serde_json::to_string_pretty(&report)?
    } else {
        serde_json::to_string(&report)?
    };
    Ok(output)
}

fn score(cli: &Cli, oracle: &Oracle, findings: &FindingsDump, target: &Path) -> MatchReport {
    let cwe_re = Regex::new(r"CWE-(\d+)").expect("regex compiles");
    let best_per_oracle = best_matches_by_oracle(oracle, findings, target, &cwe_re);

    let oracle_n = oracle.ground_truth.len().max(1);
    let scored = summarize_oracle_matches(oracle, &best_per_oracle, &cwe_re);

    // "Hits" headline metric == ±10 lines + cwe (the user-chosen primary).
    let hits = scored.counts_by_tol[1];
    let misses = oracle.ground_truth.len() - hits;

    // Near-miss: oracle entry that matched at file_only but not at ±10.
    let near_misses = scored.counts_by_tol[3].saturating_sub(scored.counts_by_tol[1]);
    let recall = recall_by_tolerance(scored.counts_by_tol, oracle_n);
    let precision = precision_for_hits(hits, findings.findings.len());
    let (proof_state_breakdown, vuln_source_breakdown) =
        primary_hit_breakdowns(&scored.matches_out);

    MatchReport {
        slice: cli.slice.clone(),
        oracle_cve: oracle.cve.clone(),
        oracle_name: oracle.name.clone(),
        oracle_commit: oracle.commit.clone(),
        findings_total: findings.findings.len(),
        hits,
        misses,
        near_misses,
        precision,
        recall,
        proof_state_breakdown,
        vuln_source_breakdown,
        matches: scored.matches_out,
        missed_oracle: scored.missed,
        expected_min_recall: oracle.expected_min_recall.unwrap_or(0.0),
        cost_usd: 0.0, // wired up in Phase 3
        wall_seconds: cli.wall_seconds,
    }
}

type OracleBestMatch<'a> = (Tolerance, &'a FindingRow, i64, bool);

struct ScoredMatches {
    counts_by_tol: [usize; 4],
    matches_out: Vec<MatchRow>,
    missed: Vec<MissedOracle>,
}

fn best_matches_by_oracle<'a>(
    oracle: &Oracle,
    findings: &'a FindingsDump,
    target: &Path,
    cwe_re: &Regex,
) -> Vec<Option<OracleBestMatch<'a>>> {
    let mut best_per_oracle = vec![None; oracle.ground_truth.len()];

    for finding in &findings.findings {
        let rel = relativise(&finding.file_path, target);
        let finding_cwes = extract_cwes(cwe_re, finding);

        for (idx, entry) in oracle.ground_truth.iter().enumerate() {
            let Some(candidate) = match_oracle_entry(finding, &finding_cwes, &rel, entry) else {
                continue;
            };
            best_per_oracle[idx] =
                Some(choose_better_match(best_per_oracle[idx].take(), candidate));
        }
    }

    best_per_oracle
}

fn match_oracle_entry<'a>(
    finding: &'a FindingRow,
    finding_cwes: &[String],
    relative_path: &str,
    entry: &OracleEntry,
) -> Option<OracleBestMatch<'a>> {
    if !path_matches(relative_path, &entry.file) {
        return None;
    }

    let cwe_match = cwes_match(finding_cwes, &entry.cwe);
    let delta = finding.start_line as i64 - entry.line_start as i64;
    let tolerance = tolerance_for_match(finding.start_line, delta, finding_cwes, entry, cwe_match);
    Some((tolerance, finding, delta, cwe_match))
}

fn choose_better_match<'a>(
    previous: Option<OracleBestMatch<'a>>,
    candidate: OracleBestMatch<'a>,
) -> OracleBestMatch<'a> {
    match previous {
        Some(prev) if prev.0.priority() >= candidate.0.priority() => prev,
        _ => candidate,
    }
}

fn tolerance_for_match(
    finding_line: u32,
    delta: i64,
    finding_cwes: &[String],
    entry: &OracleEntry,
    cwe_match: bool,
) -> Tolerance {
    let abs_delta = delta.abs();
    if entry.line_start == 0 {
        Tolerance::FileOnly
    } else if abs_delta == 0 && cwe_match_or_no_oracle_cwe(finding_cwes, &entry.cwe) {
        Tolerance::ExactLine
    } else if abs_delta <= PM_LINES_PRIMARY && cwe_match {
        Tolerance::PmLines
    } else if abs_delta <= PM_LINES_FUNCTION_FALLBACK && cwe_match {
        Tolerance::Function
    } else if line_in_oracle_range(finding_line, entry) {
        Tolerance::Function
    } else {
        Tolerance::FileOnly
    }
}

fn summarize_oracle_matches(
    oracle: &Oracle,
    best_per_oracle: &[Option<OracleBestMatch<'_>>],
    cwe_re: &Regex,
) -> ScoredMatches {
    let mut scored = ScoredMatches {
        counts_by_tol: [0usize; 4],
        matches_out: Vec::new(),
        missed: Vec::new(),
    };

    for (idx, slot) in best_per_oracle.iter().enumerate() {
        match slot {
            Some((tol, finding, delta, cwe_match)) => {
                count_tolerance_hit(&mut scored.counts_by_tol, *tol);
                scored.matches_out.push(match_row(
                    idx, *tol, finding, *delta, *cwe_match, oracle, cwe_re,
                ));
            }
            None => scored
                .missed
                .push(missed_oracle(idx, &oracle.ground_truth[idx])),
        }
    }

    scored
}

fn count_tolerance_hit(counts_by_tol: &mut [usize; 4], tolerance: Tolerance) {
    for count in &mut counts_by_tol[tolerance.count_start_index()..] {
        *count += 1;
    }
}

fn match_row(
    oracle_idx: usize,
    tolerance: Tolerance,
    finding: &FindingRow,
    delta: i64,
    cwe_match: bool,
    oracle: &Oracle,
    cwe_re: &Regex,
) -> MatchRow {
    MatchRow {
        oracle_idx,
        finding_fingerprint: finding.fingerprint.clone(),
        finding_rule_id: finding.rule_id.clone(),
        finding_tool: finding.tool.clone(),
        file: finding.file_path.clone(),
        finding_line: finding.start_line,
        oracle_line: oracle.ground_truth[oracle_idx].line_start,
        delta,
        best_tolerance: tolerance.as_str().to_string(),
        cwe_match,
        finding_cwes: extract_cwes(cwe_re, finding),
        oracle_cwes: oracle.ground_truth[oracle_idx].cwe.clone(),
        vuln_source: finding.vuln_source.clone(),
        static_proof_state: finding.static_proof_state.clone(),
    }
}

fn missed_oracle(idx: usize, entry: &OracleEntry) -> MissedOracle {
    MissedOracle {
        idx,
        file: entry.file.clone(),
        function: entry.function.clone(),
        line_start: entry.line_start,
        cwe: entry.cwe.clone(),
    }
}

fn recall_by_tolerance(counts_by_tol: [usize; 4], oracle_n: usize) -> RecallByTolerance {
    RecallByTolerance {
        exact_line: counts_by_tol[0] as f64 / oracle_n as f64,
        pm_lines: counts_by_tol[1] as f64 / oracle_n as f64,
        function_: counts_by_tol[2] as f64 / oracle_n as f64,
        file_only: counts_by_tol[3] as f64 / oracle_n as f64,
    }
}

fn precision_for_hits(hits: usize, findings_total: usize) -> f64 {
    if findings_total == 0 {
        0.0
    } else {
        hits as f64 / findings_total as f64
    }
}

fn primary_hit_breakdowns(
    matches_out: &[MatchRow],
) -> (ProofStateBreakdown, BTreeMap<String, usize>) {
    let mut proof_state_breakdown = ProofStateBreakdown::default();
    let mut vuln_source_breakdown = BTreeMap::new();

    for row in matches_out.iter().filter(|row| is_primary_hit(row)) {
        increment_proof_state_breakdown(&mut proof_state_breakdown, row);
        increment_vuln_source_breakdown(&mut vuln_source_breakdown, row);
    }

    (proof_state_breakdown, vuln_source_breakdown)
}

fn is_primary_hit(row: &MatchRow) -> bool {
    row.best_tolerance == "exact_line" || row.best_tolerance == "pm_lines"
}

fn increment_proof_state_breakdown(breakdown: &mut ProofStateBreakdown, row: &MatchRow) {
    match row.static_proof_state.as_deref() {
        Some("validated") | Some("statically_confirmed") => breakdown.validated += 1,
        Some(_) => breakdown.other_static += 1,
        None => breakdown.llm_only += 1,
    }
}

fn increment_vuln_source_breakdown(breakdown: &mut BTreeMap<String, usize>, row: &MatchRow) {
    let key = row
        .vuln_source
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    *breakdown.entry(key).or_insert(0) += 1;
}

#[derive(Copy, Clone, Debug)]
enum Tolerance {
    ExactLine,
    PmLines,
    Function,
    FileOnly,
}
impl Tolerance {
    fn priority(self) -> u8 {
        match self {
            Self::ExactLine => 4,
            Self::PmLines => 3,
            Self::Function => 2,
            Self::FileOnly => 1,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::ExactLine => "exact_line",
            Self::PmLines => "pm_lines",
            Self::Function => "function",
            Self::FileOnly => "file_only",
        }
    }
    fn count_start_index(self) -> usize {
        match self {
            Self::ExactLine => 0,
            Self::PmLines => 1,
            Self::Function => 2,
            Self::FileOnly => 3,
        }
    }
}

fn relativise(path: &str, target: &Path) -> String {
    if let Ok(p) = Path::new(path).canonicalize() {
        if let Ok(rel) = p.strip_prefix(target) {
            return rel.to_string_lossy().into_owned();
        }
    }
    // Fall through — already relative or canonicalisation failed (file removed, etc.).
    path.trim_start_matches("./").to_string()
}

fn path_matches(finding_path: &str, oracle_path: &str) -> bool {
    let normalized_finding = finding_path.trim_start_matches("./");
    let normalized_oracle = oracle_path.trim_start_matches("./");

    if normalized_oracle.ends_with('/')
        || (!normalized_oracle.contains('.') && !normalized_oracle.is_empty())
    {
        // Directory-level oracle: file is in scope if it starts with the oracle prefix.
        let prefix = normalized_oracle.trim_end_matches('/');
        if prefix.is_empty() {
            return true;
        }
        return normalized_finding == prefix
            || normalized_finding.starts_with(&format!("{prefix}/"));
    }

    normalized_finding == normalized_oracle
        || normalized_finding.ends_with(&format!("/{normalized_oracle}"))
}

fn extract_cwes(re: &Regex, f: &FindingRow) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for hay in [&f.message, &f.rule_id, &f.title] {
        for cap in re.captures_iter(hay) {
            if let Some(num) = cap.get(1) {
                out.insert(format!("CWE-{}", num.as_str()));
            }
        }
    }
    out.into_iter().collect()
}

fn cwes_match(finding_cwes: &[String], oracle_cwes: &[String]) -> bool {
    if oracle_cwes.is_empty() {
        return true; // oracle is permissive
    }
    if finding_cwes.is_empty() {
        return false; // oracle wants a CWE; finding has none
    }
    finding_cwes
        .iter()
        .any(|f| oracle_cwes.iter().any(|o| eq_ignore_case(f, o)))
}

fn cwe_match_or_no_oracle_cwe(finding_cwes: &[String], oracle_cwes: &[String]) -> bool {
    oracle_cwes.is_empty() || cwes_match(finding_cwes, oracle_cwes)
}

fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn line_in_oracle_range(line: u32, e: &OracleEntry) -> bool {
    e.line_start > 0 && e.line_end >= e.line_start && line >= e.line_start && line <= e.line_end
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding_row(file: &str, line: u32, message: &str) -> FindingRow {
        FindingRow {
            fingerprint: format!("fp-{file}-{line}"),
            rule_id: "test.rule".to_string(),
            title: String::new(),
            severity: "high".to_string(),
            file_path: file.to_string(),
            start_line: line,
            end_line: Some(line),
            message: message.to_string(),
            tool: "semgrep".to_string(),
            vuln_source: None,
            static_proof_state: None,
        }
    }

    fn cli() -> Cli {
        Cli {
            oracle: PathBuf::from("/tmp/o.json"),
            findings: PathBuf::from("/tmp/f.json"),
            slice: "test".to_string(),
            target: PathBuf::from("/tmp"),
            wall_seconds: 0,
            pretty: true,
        }
    }

    #[test]
    fn tolerance_priority_and_labels_are_ordered_by_match_strength() {
        assert_eq!(Tolerance::ExactLine.priority(), 4);
        assert_eq!(Tolerance::PmLines.priority(), 3);
        assert_eq!(Tolerance::Function.priority(), 2);
        assert_eq!(Tolerance::FileOnly.priority(), 1);
        assert_eq!(Tolerance::ExactLine.as_str(), "exact_line");
        assert_eq!(Tolerance::FileOnly.as_str(), "file_only");
    }

    #[test]
    fn path_matches_directory_oracle() {
        assert!(path_matches("crypto/skcipher.c", "crypto/"));
        assert!(path_matches("crypto/sub/foo.c", "crypto/"));
        assert!(!path_matches("lib/foo.c", "crypto/"));
    }

    #[test]
    fn cwe_extraction_pulls_from_message_rule_and_title() {
        let re = Regex::new(r"CWE-(\d+)").unwrap();
        let mut f = finding_row("foo.c", 1, "OOB write CWE-787 in handler");
        f.rule_id = "checks.cwe-78.shell-injection".to_string();
        f.title = "command injection (CWE-78)".to_string();
        let cwes = extract_cwes(&re, &f);
        assert!(cwes.contains(&"CWE-78".to_string()));
        assert!(cwes.contains(&"CWE-787".to_string()));
    }

    #[test]
    fn score_emits_pm10_hit_when_finding_within_window_with_cwe() {
        let oracle = Oracle {
            cve: "CVE-TEST".to_string(),
            slice: Some("test".to_string()),
            name: None,
            commit: None,
            ground_truth: vec![OracleEntry {
                file: "src/foo.c".to_string(),
                function: String::new(),
                line_start: 100,
                line_end: 100,
                cwe: vec!["CWE-78".to_string()],
                kind: String::new(),
                notes: String::new(),
            }],
            expected_min_recall: None,
            notes: None,
        };
        let dump = FindingsDump {
            count: 1,
            findings: vec![finding_row(
                "src/foo.c",
                105,
                "command injection CWE-78 via exec()",
            )],
        };
        let report = score(&cli(), &oracle, &dump, Path::new("/tmp"));
        assert_eq!(report.hits, 1);
        assert_eq!(report.recall.pm_lines, 1.0);
        assert_eq!(report.recall.exact_line, 0.0);
    }

    #[test]
    fn load_match_report_reads_json_files_and_renderer_respects_pretty_flag() {
        let temp = std::env::temp_dir().join(format!(
            "kuzushi-eval-load-report-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        let oracle = temp.join("oracle.json");
        let findings = temp.join("findings.json");
        std::fs::write(
            &oracle,
            r#"{
                "cve":"CVE-TEST",
                "ground_truth":[{
                    "file":"src/foo.c",
                    "line_start":10,
                    "line_end":10,
                    "cwe":["CWE-787"]
                }]
            }"#,
        )
        .unwrap();
        std::fs::write(
            &findings,
            r#"{
                "count":1,
                "findings":[{
                    "fingerprint":"fp",
                    "rule_id":"test.cwe-787",
                    "severity":"high",
                    "file_path":"src/foo.c",
                    "start_line":10,
                    "message":"CWE-787",
                    "tool":"semgrep"
                }]
            }"#,
        )
        .unwrap();
        let cli = Cli {
            oracle,
            findings,
            slice: "test".to_string(),
            target: temp,
            wall_seconds: 0,
            pretty: false,
        };

        let report = load_match_report(&cli).unwrap();
        assert_eq!(report.hits, 1);
        assert!(!render_match_report(&report, false).unwrap().contains('\n'));
        assert!(render_match_report(&report, true).unwrap().contains('\n'));
    }

    #[test]
    fn score_demotes_to_file_only_when_cwe_mismatched() {
        let oracle = Oracle {
            cve: "CVE-TEST".to_string(),
            slice: Some("test".to_string()),
            name: None,
            commit: None,
            ground_truth: vec![OracleEntry {
                file: "src/foo.c".to_string(),
                function: String::new(),
                line_start: 100,
                line_end: 100,
                cwe: vec!["CWE-78".to_string()],
                kind: String::new(),
                notes: String::new(),
            }],
            expected_min_recall: None,
            notes: None,
        };
        let dump = FindingsDump {
            count: 1,
            findings: vec![finding_row(
                "src/foo.c",
                105,
                "XSS CWE-79 via reflected input",
            )],
        };
        let report = score(&cli(), &oracle, &dump, Path::new("/tmp"));
        assert_eq!(report.recall.pm_lines, 0.0);
        assert_eq!(report.recall.file_only, 1.0);
    }

    #[test]
    fn score_proof_state_breakdown_partitions_primary_hits() {
        let oracle = Oracle {
            cve: "CVE-TEST".to_string(),
            slice: Some("test".to_string()),
            name: None,
            commit: None,
            ground_truth: vec![
                OracleEntry {
                    file: "src/a.c".to_string(),
                    function: String::new(),
                    line_start: 10,
                    line_end: 10,
                    cwe: vec!["CWE-78".to_string()],
                    kind: String::new(),
                    notes: String::new(),
                },
                OracleEntry {
                    file: "src/b.c".to_string(),
                    function: String::new(),
                    line_start: 20,
                    line_end: 20,
                    cwe: vec!["CWE-78".to_string()],
                    kind: String::new(),
                    notes: String::new(),
                },
                OracleEntry {
                    file: "src/c.c".to_string(),
                    function: String::new(),
                    line_start: 30,
                    line_end: 30,
                    cwe: vec!["CWE-78".to_string()],
                    kind: String::new(),
                    notes: String::new(),
                },
            ],
            expected_min_recall: None,
            notes: None,
        };
        let mut validated = finding_row("src/a.c", 10, "CWE-78 exec");
        validated.static_proof_state = Some("statically_confirmed".to_string());
        validated.vuln_source = Some("ainalysis".to_string());
        let mut other_static = finding_row("src/b.c", 20, "CWE-78 exec");
        other_static.static_proof_state = Some("signal_only".to_string());
        let llm_only = finding_row("src/c.c", 30, "CWE-78 exec");
        let dump = FindingsDump {
            count: 3,
            findings: vec![validated, other_static, llm_only],
        };
        let report = score(&cli(), &oracle, &dump, Path::new("/tmp"));
        assert_eq!(report.hits, 3);
        assert_eq!(report.proof_state_breakdown.validated, 1);
        assert_eq!(report.proof_state_breakdown.other_static, 1);
        assert_eq!(report.proof_state_breakdown.llm_only, 1);
        assert_eq!(report.vuln_source_breakdown.get("ainalysis"), Some(&1));
        assert_eq!(report.vuln_source_breakdown.get("unknown"), Some(&2));
    }
}
