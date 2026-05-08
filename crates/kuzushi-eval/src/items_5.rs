use super::prelude::*;
use super::*;

pub(crate) fn primary_hit_breakdowns(
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

pub(crate) fn is_primary_hit(row: &MatchRow) -> bool {
    row.best_tolerance == "exact_line" || row.best_tolerance == "pm_lines"
}

pub(crate) fn increment_proof_state_breakdown(breakdown: &mut ProofStateBreakdown, row: &MatchRow) {
    match row.static_proof_state.as_deref() {
        Some("validated") | Some("statically_confirmed") => breakdown.validated += 1,
        Some(_) => breakdown.other_static += 1,
        None => breakdown.llm_only += 1,
    }
}

pub(crate) fn increment_vuln_source_breakdown(
    breakdown: &mut BTreeMap<String, usize>,
    row: &MatchRow,
) {
    let key = row
        .vuln_source
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    *breakdown.entry(key).or_insert(0) += 1;
}

#[derive(Copy, Clone, Debug)]
pub(crate) enum Tolerance {
    ExactLine,
    PmLines,
    Function,
    FileOnly,
}

impl Tolerance {
    pub(crate) fn priority(self) -> u8 {
        match self {
            Self::ExactLine => 4,
            Self::PmLines => 3,
            Self::Function => 2,
            Self::FileOnly => 1,
        }
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ExactLine => "exact_line",
            Self::PmLines => "pm_lines",
            Self::Function => "function",
            Self::FileOnly => "file_only",
        }
    }
    pub(crate) fn count_start_index(self) -> usize {
        match self {
            Self::ExactLine => 0,
            Self::PmLines => 1,
            Self::Function => 2,
            Self::FileOnly => 3,
        }
    }
}

pub(crate) fn relativise(path: &str, target: &Path) -> String {
    if let Ok(p) = Path::new(path).canonicalize() {
        if let Ok(rel) = p.strip_prefix(target) {
            return rel.to_string_lossy().into_owned();
        }
    }
    // Fall through — already relative or canonicalisation failed (file removed, etc.).
    path.trim_start_matches("./").to_string()
}

pub(crate) fn path_matches(finding_path: &str, oracle_path: &str) -> bool {
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

pub(crate) fn extract_cwes(re: &Regex, f: &FindingRow) -> Vec<String> {
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
