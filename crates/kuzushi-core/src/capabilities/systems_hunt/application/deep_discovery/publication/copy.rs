pub(super) fn withheld_output(original: &str, reason: &str, partial: bool) -> String {
    let action = if partial {
        "Inspect the ledger for earlier inserts and the unpublished candidates in Replay. Further work needs separate approval."
    } else {
        "Inspect unpublished candidates in Replay. Further work needs separate approval."
    };
    format!("{reason}\n\n{action}\n\nHISTORICAL CANDIDATE OUTPUT\nThis output records the earlier analysis, not a ledger insertion.\n{original}")
}

pub(super) fn bytes(value: usize) -> String {
    let units = [(1024 * 1024, "MiB"), (1024, "KiB")];
    match units
        .into_iter()
        .find(|(scale, _)| value > 0 && value.is_multiple_of(*scale))
    {
        Some((scale, unit)) => format!("{} {unit}", value / scale),
        None => format!("{value} B"),
    }
}

pub(super) fn published_output(original: &str, count: usize) -> String {
    let action = if count == 0 {
        "No new candidates in this pass. Previous findings and decisions remain in the ledger. Review scope and coverage before any additional work."
    } else {
        super::super::render::LEDGER_GUIDANCE
    };
    format!("{action}\n\n{original}")
}

#[cfg(test)]
mod tests {
    use super::super::super::render::LEDGER_GUIDANCE;
    use super::*;

    #[test]
    fn withheld_guidance_never_directs_an_unpublished_candidate_to_the_ledger() {
        let original = "one historical candidate\nFROZEN MODEL INPUT\nowned source";
        let output = withheld_output(&original, "Capture limit 1 B", false);
        assert!(!output.contains(LEDGER_GUIDANCE));
        assert!(output.contains("Inspect unpublished candidates in Replay"));
        assert!(output.contains("HISTORICAL CANDIDATE OUTPUT"));
        assert!(output.ends_with("FROZEN MODEL INPUT\nowned source"));
        let partial = withheld_output(&original, "Storage failed", true);
        assert!(partial.contains("Inspect the ledger for earlier inserts"));
        assert!(!partial.contains(LEDGER_GUIDANCE));
        let supplied_source = format!("{original}\n{LEDGER_GUIDANCE}");
        assert!(
            withheld_output(&supplied_source, "Capture limit", false).ends_with(&supplied_source)
        );
    }

    #[test]
    fn byte_labels_preserve_exact_limits_without_rounding() {
        for (value, label) in [
            (0, "0 B"),
            (122, "122 B"),
            (1024, "1 KiB"),
            (1025, "1025 B"),
            (16 * 1024 * 1024, "16 MiB"),
        ] {
            assert_eq!(bytes(value), label);
        }
    }
}
