use super::*;

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Unknown,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_semgrep(value: &str) -> Self {
        Self::from_label(value)
    }

    /// The one severity-label parser. Every scanner-native and LLM-emitted
    /// severity string in the repository resolves through here, so the same
    /// label lands in the same band whichever engine reported it — a finding
    /// that fails to parse becomes [`Severity::Unknown`], and an `Unknown`
    /// finding can never trip `scan --fail-on` or `kuzushi ci`. One engine
    /// banding a label another engine drops is therefore a gating difference,
    /// not a cosmetic one.
    ///
    /// Covers the Semgrep (`ERROR`/`WARNING`/`INFO`), CodeQL/SARIF
    /// (`note`/`warning`/`error`) and plain (`critical`…`info`) vocabularies,
    /// and the short and long spellings models emit for them. Labels outside
    /// that vocabulary fail closed rather than being mapped to a plausible
    /// band.
    pub fn from_label(value: &str) -> Self {
        match normalized_severity_label(value).as_str() {
            "critical" | "crit" => Self::Critical,
            "high" | "error" => Self::High,
            "medium" | "med" | "warning" | "warn" => Self::Medium,
            "low" => Self::Low,
            "info" | "information" | "informational" | "note" => Self::Info,
            "unknown" => Self::Unknown,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
            Self::Unknown => "unknown",
        }
    }
}

impl TryFrom<&str> for Severity {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        let severity = Self::from_label(value);
        if severity == Self::Unknown && normalized_severity_label(value) != "unknown" {
            anyhow::bail!("unknown severity {value:?}");
        }
        Ok(severity)
    }
}

fn normalized_severity_label(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .replace(['_', '-'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_label_parser_maps_common_scanner_aliases() {
        assert_eq!(Severity::from_label("ERROR"), Severity::High);
        assert_eq!(Severity::from_label("warn"), Severity::Medium);
        assert_eq!(Severity::from_label("informational"), Severity::Info);
        assert_eq!(Severity::from_label("surprising"), Severity::Unknown);
    }

    #[test]
    fn severity_order_treats_unknown_as_lowest_risk() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
        assert!(Severity::Info > Severity::Unknown);
    }
}

#[cfg(test)]
mod scanner_label_tests {
    use super::Severity;

    #[test]
    fn semgrep_and_legacy_labels_normalize_to_canonical_bands() {
        // Semgrep-native
        assert_eq!(Severity::from_label("ERROR"), Severity::High);
        assert_eq!(Severity::from_label("WARNING"), Severity::Medium);
        assert_eq!(Severity::from_label("INFO"), Severity::Info);
        // Legacy / CodeQL-style
        assert_eq!(Severity::from_label("HIGH"), Severity::High);
        assert_eq!(Severity::from_label("medium"), Severity::Medium);
        assert_eq!(Severity::from_label("Low"), Severity::Low);
        assert_eq!(Severity::from_label("CRITICAL"), Severity::Critical);
        // Fail closed on unknown labels rather than guessing a band.
        assert_eq!(Severity::from_label("bogus"), Severity::Unknown);
    }

    /// `INFORMATION` only ever reached a band through the retired
    /// scanner-label copy; the one parser has to keep banding it.
    #[test]
    fn long_information_spelling_keeps_its_band() {
        assert_eq!(Severity::from_label("INFORMATION"), Severity::Info);
        assert_eq!(Severity::from_label("Informational"), Severity::Info);
    }

    /// The vocabulary the retired copies dropped, read through an engine
    /// adapter that used to carry one. Each of these banded through
    /// `systems-hunt` and fell to `Unknown` through `agentic-sast`, and an
    /// `Unknown` finding can never trip `scan --fail-on` or `kuzushi ci`.
    /// The last two stay `Unknown` on both sides: the parser fails closed
    /// rather than guessing at a band it was never given.
    #[test]
    fn spellings_the_retired_copies_dropped_now_band() {
        for (label, expected) in [
            ("crit", Severity::Critical),
            ("warn", Severity::Medium),
            ("note", Severity::Info),
            ("\"high\"", Severity::High),
            ("very_high", Severity::Unknown),
            ("MEDIUM-HIGH", Severity::Unknown),
        ] {
            assert_eq!(
                crate::capabilities::agentic_sast::agentic_severity(label),
                expected,
                "label {label:?}"
            );
        }
    }

    /// Divergence regression guard. `uaf-hunt` carried a copy with no
    /// `ERROR`/`WARNING` at all, so a memory-safety finding labelled in
    /// Semgrep's own vocabulary banded `High` from `agentic-sast` and
    /// `Unknown` from `uaf-hunt` — the same label, two gating outcomes.
    #[test]
    fn every_engine_entry_point_bands_a_label_identically() {
        for label in [
            "ERROR", "WARNING", "warn", "note", "crit", "CRITICAL", "HIGH", "medium", "Low",
            "INFO", "INFORMATION", "bogus",
        ] {
            let canonical = Severity::from_label(label);
            assert_eq!(
                Severity::from_semgrep(label),
                canonical,
                "from_semgrep disagrees on {label:?}"
            );
            assert_eq!(
                crate::capabilities::agentic_sast::agentic_severity(label),
                canonical,
                "agentic-sast disagrees on {label:?}"
            );
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum VulnSource {
    /// Output from a SARIF-emitting scanner (semgrep, codeql, …).
    Sarif,
    /// LLM-driven per-file analysis (systems-hunt, carlini-threat-hunt).
    #[serde(rename = "analysis", alias = "ainalysis")]
    Ainalysis,
    /// LLM-driven chunked whole-codebase pass (full-mode-multi).
    #[serde(
        rename = "analysis-multi",
        alias = "analysis_multi",
        alias = "ainalysis-multi",
        alias = "ainalysis_multi"
    )]
    AinalysisMulti,
    /// Diff-scoped scan (`--since <ref>`, variant-ndiff).
    DiffAnalyzer,
    /// Reserved — Infer integration not yet wired.
    Infer,
    /// Reserved — fuzzing channel not yet wired.
    Fuzzing,
}
