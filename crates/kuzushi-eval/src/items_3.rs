use super::prelude::*;
use super::*;

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

pub(crate) type OracleBestMatch<'a> = (Tolerance, &'a FindingRow, i64, bool);

pub(crate) struct ScoredMatches {
    pub(crate) counts_by_tol: [usize; 4],
    pub(crate) matches_out: Vec<MatchRow>,
    pub(crate) missed: Vec<MissedOracle>,
}

pub(crate) fn best_matches_by_oracle<'a>(
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

pub(crate) fn match_oracle_entry<'a>(
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

pub(crate) fn choose_better_match<'a>(
    previous: Option<OracleBestMatch<'a>>,
    candidate: OracleBestMatch<'a>,
) -> OracleBestMatch<'a> {
    match previous {
        Some(prev) if prev.0.priority() >= candidate.0.priority() => prev,
        _ => candidate,
    }
}
