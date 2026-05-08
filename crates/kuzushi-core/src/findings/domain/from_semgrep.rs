use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

impl Severity {
    pub fn from_semgrep(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "ERROR" => Self::High,
            "WARNING" => Self::Medium,
            "INFO" => Self::Low,
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
        match value {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            "unknown" => Ok(Self::Unknown),
            other => anyhow::bail!("unknown severity {other:?}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum VulnSource {
    /// Output from a SARIF-emitting scanner (semgrep, codeql, …).
    Sarif,
    /// LLM-driven per-file analysis (systems-hunt, carlini-threat-hunt).
    Ainalysis,
    /// LLM-driven chunked whole-codebase pass (full-mode-multi).
    AinalysisMulti,
    /// Diff-scoped scan (`--since <ref>`, variant-ndiff).
    DiffAnalyzer,
    /// Reserved — Infer integration not yet wired.
    Infer,
    /// Reserved — fuzzing channel not yet wired.
    Fuzzing,
}
