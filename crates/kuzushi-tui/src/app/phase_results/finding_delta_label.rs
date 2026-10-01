//! Honest finding-delta labels for phase-result receipts.
//!
//! A receipt's finding count is only a measurement when every referenced run
//! committed a typed finding delta. Without that observation a zero is not a
//! clean result, so the label says `unmeasured` instead of printing `+0`.

/// `counts` is the pre-formatted count text (`+3`, or `+3 ~1 -0`) and `total`
/// its sum. `observed` is `Some(true)` for a full measurement, `Some(false)`
/// when at least one run committed no delta, and `None` for receipts written
/// before observation was recorded: their non-zero counts came from real
/// deltas, but their zero cannot be told apart from a missing one.
pub(crate) fn finding_delta_label(counts: &str, total: u64, observed: Option<bool>) -> String {
    if total == 0 && observed != Some(true) {
        return "findings unmeasured".to_string();
    }
    match observed {
        Some(false) => format!("findings {counts}, partly unmeasured"),
        _ => format!("findings {counts}"),
    }
}

/// The label for a findings count the ledger measured because no typed delta
/// did. `distinct` is what the ledger attributes to the attempt's runs: not a
/// delta, so no `+`.
///
/// It states no observation count beside it, unlike the Scan delta pane. The
/// pane sums `findings` over every summary it loaded for the attempt; the
/// receipt's `changed_findings` is `receipt_run_changes`'s `max` over the same
/// runs. Those differ the moment an attempt has two finding-producing runs, and
/// one word printed over two arithmetics is the defect this label exists to
/// fix. The pane keeps the fold disclosure, beside the severity breakdown it
/// reconciles with.
pub(crate) fn attributed_findings_label(distinct: u64) -> String {
    format!("findings {distinct} distinct")
}

#[cfg(test)]
mod tests {
    use super::{attributed_findings_label, finding_delta_label};

    #[test]
    fn a_measured_delta_prints_its_counts_even_when_zero() {
        assert_eq!(finding_delta_label("+0", 0, Some(true)), "findings +0");
        assert_eq!(finding_delta_label("+73", 73, Some(true)), "findings +73");
    }

    #[test]
    fn an_unobserved_zero_is_unmeasured_not_plus_zero() {
        assert_eq!(
            finding_delta_label("+0", 0, Some(false)),
            "findings unmeasured"
        );
    }

    #[test]
    fn a_partially_observed_count_is_disclosed_as_partial() {
        assert_eq!(
            finding_delta_label("+6", 6, Some(false)),
            "findings +6, partly unmeasured"
        );
    }

    #[test]
    fn legacy_receipts_keep_real_counts_but_never_claim_a_measured_zero() {
        assert_eq!(finding_delta_label("+4", 4, None), "findings +4");
        assert_eq!(finding_delta_label("+0", 0, None), "findings unmeasured");
    }

    #[test]
    fn a_ledger_measured_count_states_the_distinct_findings() {
        assert_eq!(attributed_findings_label(25), "findings 25 distinct");
        assert_eq!(attributed_findings_label(0), "findings 0 distinct");
    }

    #[test]
    fn a_ledger_measured_count_never_reads_as_a_delta() {
        assert!(!attributed_findings_label(25).contains('+'));
    }

    /// The receipt's count is a `max` over the attempt's runs and the Scan
    /// pane's is a sum, so this label must not restate either as the
    /// attempt's observations.
    #[test]
    fn a_ledger_measured_count_claims_no_observation_total() {
        let label = attributed_findings_label(10);
        assert!(!label.contains("observation"), "{label}");
    }
}
