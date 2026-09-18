use kuzushi_core::Severity;

/// Map a threat's `impact` onto the display band.
///
/// The threat-model normalizer owns the judgment: it canonicalizes spelling
/// inside the closed impact vocabulary, keeps an unrecognized impact verbatim
/// with a warning, and leaves `unknown` alone. An impact it did not recognize
/// therefore reaches the shell unrated, and stays [`Severity::Unknown`] here
/// rather than being read as a band the model never assigned. `info` is the
/// one value outside that vocabulary the shell still bands, because the model
/// did state it.
pub(super) fn impact_to_severity(value: &str) -> Severity {
    match value.to_lowercase().as_str() {
        "critical" | "existential" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Unknown,
    }
}

pub(super) fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
        Severity::Unknown => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_vocabulary_impacts_keep_their_band() {
        assert_eq!(impact_to_severity("existential"), Severity::Critical);
        assert_eq!(impact_to_severity("Critical"), Severity::Critical);
        assert_eq!(impact_to_severity("high"), Severity::High);
        assert_eq!(impact_to_severity("medium"), Severity::Medium);
        assert_eq!(impact_to_severity("low"), Severity::Low);
        assert_eq!(impact_to_severity("info"), Severity::Info);
    }

    #[test]
    fn an_impact_outside_the_vocabulary_is_unknown_not_medium() {
        // The normalizer writes `unknown` and keeps unrecognized values
        // verbatim; reading either as MEDIUM would mint a band the threat
        // model refused to assign.
        assert_eq!(impact_to_severity("unknown"), Severity::Unknown);
        assert_eq!(impact_to_severity("moderate"), Severity::Unknown);
        assert_eq!(impact_to_severity("catastrophic"), Severity::Unknown);
        assert_eq!(impact_to_severity(""), Severity::Unknown);
        // The normalizer recognizes no padded value either, so neither does
        // the shell: the two stay in step on what counts as rated.
        assert_eq!(impact_to_severity(" medium "), Severity::Unknown);
    }

    #[test]
    fn unknown_ranks_below_every_named_band() {
        assert_eq!(severity_rank(Severity::Unknown), 0);
        assert!(severity_rank(Severity::Info) > severity_rank(Severity::Unknown));
    }
}
