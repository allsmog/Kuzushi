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
    let entry = &oracle.ground_truth[oracle_idx];
    let labels = match_label_fields(finding, entry);
    MatchRow {
        oracle_idx,
        finding_fingerprint: finding.fingerprint.clone(),
        finding_rule_id: finding.rule_id.clone(),
        finding_tool: finding.tool.clone(),
        file: finding.file_path.clone(),
        finding_line: finding.start_line,
        oracle_line: entry.line_start,
        delta,
        best_tolerance: tolerance.as_str().to_string(),
        cwe_match,
        finding_cwes: extract_cwes(cwe_re, finding),
        oracle_cwes: entry.cwe.clone(),
        vuln_source: finding.vuln_source.clone(),
        static_proof_state: finding.static_proof_state.clone(),
        finding_verdict: labels.finding_verdict,
        expected_verdict: labels.expected_verdict,
        verdict_match: labels.verdict_match,
        finding_severity: labels.finding_severity,
        expected_severity: labels.expected_severity,
        severity_match: labels.severity_match,
    }
}

struct MatchLabelFields {
    finding_verdict: Option<String>,
    expected_verdict: Option<String>,
    verdict_match: Option<bool>,
    finding_severity: String,
    expected_severity: Option<String>,
    severity_match: Option<bool>,
}

fn match_label_fields(finding: &FindingRow, entry: &OracleEntry) -> MatchLabelFields {
    let finding_verdict = finding.verdict_label();
    let expected_verdict = entry.expected_verdict.clone();
    let expected_severity = entry.expected_severity.clone();
    MatchLabelFields {
        verdict_match: label_match(
            finding_verdict.as_deref(),
            expected_verdict.as_deref(),
            normalize_verdict_label,
        ),
        severity_match: label_match(
            Some(finding.severity.as_str()),
            expected_severity.as_deref(),
            normalize_severity_label,
        ),
        finding_severity: finding.severity.clone(),
        finding_verdict,
        expected_verdict,
        expected_severity,
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

impl FindingRow {
    pub(crate) fn verdict_label(&self) -> Option<String> {
        self.verdict
            .as_deref()
            .or_else(|| self.triage.as_ref().map(|triage| triage.verdict.as_str()))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    }
}

fn label_match(
    observed: Option<&str>,
    expected: Option<&str>,
    normalize: fn(&str) -> String,
) -> Option<bool> {
    let expected = expected.map(str::trim).filter(|value| !value.is_empty())?;
    let observed = observed.map(str::trim).filter(|value| !value.is_empty());
    Some(observed.is_some_and(|value| normalize(value) == normalize(expected)))
}

fn normalize_verdict_label(value: &str) -> String {
    match normalized_label(value).as_str() {
        "tp" | "true positive" | "truepositive" | "true_positive" | "confirmed" => "true_positive",
        "fp" | "false positive" | "falsepositive" | "false_positive" | "rejected" => {
            "false_positive"
        }
        "needs review" | "needsreview" | "needs_review" | "unknown" => "needs_review",
        "by design" | "bydesign" | "by_design" | "accepted risk" | "acceptedrisk" => "by_design",
        other => other,
    }
    .to_string()
}

fn normalize_severity_label(value: &str) -> String {
    match normalized_label(value).as_str() {
        "critical" | "crit" => "critical",
        "high" | "error" => "high",
        "medium" | "med" | "warning" | "warn" => "medium",
        "low" => "low",
        "info" | "informational" | "note" => "info",
        "unknown" => "unknown",
        other => other,
    }
    .to_string()
}

fn normalized_label(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .replace(['-', '_'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

pub(crate) fn precision_for_hits(hits: usize, findings_total: usize) -> f64 {
    if findings_total == 0 {
        0.0
    } else {
        hits as f64 / findings_total as f64
    }
}
