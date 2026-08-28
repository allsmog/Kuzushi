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

    pub fn from_label(value: &str) -> Self {
        match normalized_severity_label(value).as_str() {
            "critical" | "crit" => Self::Critical,
            "high" | "error" => Self::High,
            "medium" | "med" | "warning" | "warn" => Self::Medium,
            "low" => Self::Low,
            "info" | "informational" | "note" => Self::Info,
            "unknown" => Self::Unknown,
            _ => Self::Unknown,
        }
    }

    /// Canonicalize any scanner-native or LLM-emitted severity label to the
    /// canonical band. Handles Semgrep (`ERROR`/`WARNING`/`INFO`) and legacy /
    /// CodeQL-style (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`) vocabularies in one place.
    /// Unknown labels fail closed to [`Severity::Unknown`] rather than being
    /// silently mapped to a plausible band.
    pub fn from_scanner_label(value: &str) -> Self {
        match value.trim().to_ascii_uppercase().as_str() {
            "CRITICAL" => Self::Critical,
            "ERROR" | "HIGH" => Self::High,
            "WARNING" | "MEDIUM" | "MED" => Self::Medium,
            "LOW" => Self::Low,
            "INFO" | "INFORMATION" | "INFORMATIONAL" => Self::Info,
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
        assert_eq!(Severity::from_scanner_label("ERROR"), Severity::High);
        assert_eq!(Severity::from_scanner_label("WARNING"), Severity::Medium);
        assert_eq!(Severity::from_scanner_label("INFO"), Severity::Info);
        // Legacy / CodeQL-style
        assert_eq!(Severity::from_scanner_label("HIGH"), Severity::High);
        assert_eq!(Severity::from_scanner_label("medium"), Severity::Medium);
        assert_eq!(Severity::from_scanner_label("Low"), Severity::Low);
        assert_eq!(Severity::from_scanner_label("CRITICAL"), Severity::Critical);
        // Fail closed on unknown labels rather than guessing a band.
        assert_eq!(Severity::from_scanner_label("bogus"), Severity::Unknown);
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
