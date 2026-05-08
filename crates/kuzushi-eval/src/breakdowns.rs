use std::collections::BTreeMap;

use crate::{MatchRow, ProofStateBreakdown};

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
