use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingVerdictFilter {
    TruePositive,
    FalsePositive,
    NeedsReview,
    ByDesign,
}

impl FindingVerdictFilter {
    pub fn from_input(value: &str) -> Result<Self> {
        match value.trim() {
            "tp" | "true_positive" | "vulnerable" => Ok(Self::TruePositive),
            "fp" | "false_positive" | "safe" => Ok(Self::FalsePositive),
            "needs_review" | "review" | "detected" => Ok(Self::NeedsReview),
            "by_design" | "by-design" => Ok(Self::ByDesign),
            other => anyhow::bail!("unknown findings:list verdict filter {other:?}"),
        }
    }

    pub(in crate::findings) fn from_finding(finding: &Finding) -> Self {
        match finding.triage.as_ref().map(|triage| triage.verdict) {
            Some(TriageVerdict::TruePositive) => Self::TruePositive,
            Some(TriageVerdict::FalsePositive) => Self::FalsePositive,
            Some(TriageVerdict::NeedsReview) | None => Self::NeedsReview,
            Some(TriageVerdict::ByDesign) => Self::ByDesign,
        }
    }

    pub(in crate::findings) fn as_legacy_str(self) -> &'static str {
        match self {
            Self::TruePositive => "tp",
            Self::FalsePositive => "fp",
            Self::NeedsReview => "needs_review",
            Self::ByDesign => "by_design",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingTriageStateFilter {
    Untriaged,
    Triaged,
}

impl FindingTriageStateFilter {
    pub fn from_input(value: &str) -> Result<Self> {
        match value.trim() {
            "new" | "pending" | "untriaged" => Ok(Self::Untriaged),
            "triaged" | "classified" => Ok(Self::Triaged),
            other => anyhow::bail!("unknown findings:list state filter {other:?}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingListFilter {
    pub severity: Vec<Severity>,
    pub verdict: Vec<FindingVerdictFilter>,
    pub triage_state: Vec<FindingTriageStateFilter>,
    pub name: Option<String>,
    pub text_terms: Vec<String>,
    pub file_path: Option<String>,
    pub run_id: Vec<String>,
    /// Filter by discovery channel(s). Empty = no filter.
    pub vuln_source: Vec<VulnSource>,
    pub limit: usize,
}

impl Default for FindingListFilter {
    fn default() -> Self {
        Self {
            severity: Vec::new(),
            verdict: Vec::new(),
            triage_state: Vec::new(),
            name: None,
            text_terms: Vec::new(),
            file_path: None,
            run_id: Vec::new(),
            vuln_source: Vec::new(),
            limit: 50,
        }
    }
}
