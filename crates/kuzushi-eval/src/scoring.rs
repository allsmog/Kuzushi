use regex::Regex;
use std::path::Path;

use crate::{
    best_matches_by_oracle, label_accuracy, precision_for_hits, primary_hit_breakdowns,
    recall_by_tolerance, summarize_oracle_matches, Cli, FindingRow, FindingsDump, MatchReport,
    Oracle, OracleEntry, Tolerance,
};

pub(crate) fn score(
    cli: &Cli,
    oracle: &Oracle,
    findings: &FindingsDump,
    target: &Path,
) -> MatchReport {
    let cwe_re = Regex::new(r"CWE-(\d+)").expect("regex compiles");
    let best_per_oracle = best_matches_by_oracle(oracle, findings, target, &cwe_re);
    let oracle_n = oracle.ground_truth.len().max(1);
    let scored = summarize_oracle_matches(oracle, &best_per_oracle, &cwe_re);

    let hits = scored.counts_by_tol[1];
    let misses = oracle.ground_truth.len() - hits;
    let near_misses = scored.counts_by_tol[3].saturating_sub(scored.counts_by_tol[1]);
    let recall = recall_by_tolerance(scored.counts_by_tol, oracle_n);
    let precision = precision_for_hits(hits, findings.findings.len());
    let (proof_state_breakdown, vuln_source_breakdown) =
        primary_hit_breakdowns(&scored.matches_out);
    let label_accuracy = label_accuracy(&scored.matches_out);

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
        label_accuracy,
        matches: scored.matches_out,
        missed_oracle: scored.missed,
        expected_min_recall: oracle.expected_min_recall.unwrap_or(0.0),
        cost_usd: cli.cost_usd,
        wall_seconds: cli.wall_seconds,
    }
}

pub(crate) type OracleBestMatch<'a> = (Tolerance, &'a FindingRow, i64, bool);

pub(crate) struct ScoredMatches {
    pub(crate) counts_by_tol: [usize; 4],
    pub(crate) matches_out: Vec<crate::MatchRow>,
    pub(crate) missed: Vec<crate::MissedOracle>,
}

pub(crate) fn match_oracle_entry<'a>(
    finding: &'a FindingRow,
    finding_cwes: &[String],
    relative_path: &str,
    entry: &OracleEntry,
) -> Option<OracleBestMatch<'a>> {
    if !crate::path_matches(relative_path, &entry.file) {
        return None;
    }

    let cwe_match = crate::cwes_match(finding_cwes, &entry.cwe);
    let delta = finding.start_line as i64 - entry.line_start as i64;
    let tolerance =
        crate::tolerance_for_match(finding.start_line, delta, finding_cwes, entry, cwe_match);
    Some((tolerance, finding, delta, cwe_match))
}

pub(crate) fn choose_better_match<'a>(
    previous: Option<OracleBestMatch<'a>>,
    candidate: OracleBestMatch<'a>,
) -> OracleBestMatch<'a> {
    match previous {
        Some(prev) if prev.0.priority() >= candidate.0.priority() => prev,
        _ => candidate,
    }
}
