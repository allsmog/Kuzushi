use regex::Regex;
use std::path::Path;

use crate::{
    choose_better_match, extract_cwes, match_oracle_entry, relativise, FindingRow, FindingsDump,
    MatchRow, MissedOracle, Oracle, OracleBestMatch, OracleEntry, RecallByTolerance, ScoredMatches,
    Tolerance,
};

pub(crate) fn best_matches_by_oracle<'a>(
    oracle: &Oracle,
    findings: &'a FindingsDump,
    target: &Path,
    cwe_re: &Regex,
) -> Vec<Option<OracleBestMatch<'a>>> {
    let mut best_per_oracle = vec![None; oracle.ground_truth.len()];
    for finding in &findings.findings {
        update_best_matches_for_finding(finding, oracle, target, cwe_re, &mut best_per_oracle);
    }
    best_per_oracle
}

fn update_best_matches_for_finding<'a>(
    finding: &'a FindingRow,
    oracle: &Oracle,
    target: &Path,
    cwe_re: &Regex,
    best_per_oracle: &mut [Option<OracleBestMatch<'a>>],
) {
    let rel = relativise(&finding.file_path, target);
    let finding_cwes = extract_cwes(cwe_re, finding);
    for (idx, entry) in oracle.ground_truth.iter().enumerate() {
        let Some(candidate) = match_oracle_entry(finding, &finding_cwes, &rel, entry) else {
            continue;
        };
        best_per_oracle[idx] = Some(choose_better_match(best_per_oracle[idx].take(), candidate));
    }
}

pub(crate) fn summarize_oracle_matches(
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
        summarize_oracle_slot(idx, slot, oracle, cwe_re, &mut scored);
    }
    scored
}

fn summarize_oracle_slot(
    idx: usize,
    slot: &Option<OracleBestMatch<'_>>,
    oracle: &Oracle,
    cwe_re: &Regex,
    scored: &mut ScoredMatches,
) {
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

pub(crate) fn count_tolerance_hit(counts_by_tol: &mut [usize; 4], tolerance: Tolerance) {
    for count in &mut counts_by_tol[tolerance.count_start_index()..] {
        *count += 1;
    }
}

pub(crate) fn match_row(
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

pub(crate) fn missed_oracle(idx: usize, entry: &OracleEntry) -> MissedOracle {
    MissedOracle {
        idx,
        file: entry.file.clone(),
        function: entry.function.clone(),
        line_start: entry.line_start,
        cwe: entry.cwe.clone(),
    }
}

pub(crate) fn recall_by_tolerance(counts_by_tol: [usize; 4], oracle_n: usize) -> RecallByTolerance {
    RecallByTolerance {
        exact_line: counts_by_tol[0] as f64 / oracle_n as f64,
        pm_lines: counts_by_tol[1] as f64 / oracle_n as f64,
        function_: counts_by_tol[2] as f64 / oracle_n as f64,
        file_only: counts_by_tol[3] as f64 / oracle_n as f64,
    }
}

pub(crate) fn precision_for_hits(hits: usize, findings_total: usize) -> f64 {
    if findings_total == 0 {
        0.0
    } else {
        hits as f64 / findings_total as f64
    }
}
