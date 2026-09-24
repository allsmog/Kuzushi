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

#[cfg(test)]
mod tests {
    use super::finding_delta_label;

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
}
