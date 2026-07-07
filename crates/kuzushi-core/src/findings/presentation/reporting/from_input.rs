use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingVerdictFilter {
    TruePositive,
    FalsePositive,
    NeedsReview,
    ByDesign,
    Suppressed,
    Deferred,
}

impl FindingVerdictFilter {
    pub fn from_input(value: &str) -> Result<Self> {
        match value.trim() {
            "tp" | "true_positive" | "vulnerable" | "confirmed" => Ok(Self::TruePositive),
            "fp" | "false_positive" | "safe" | "rejected_false_positive" => {
                Ok(Self::FalsePositive)
            }
            "needs_review" | "review" | "detected" => Ok(Self::NeedsReview),
            "by_design" | "by-design" | "accepted_risk" => Ok(Self::ByDesign),
            "suppressed" => Ok(Self::Suppressed),
            "deferred" => Ok(Self::Deferred),
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

    pub(in crate::findings) fn from_review_decision(
        decision: ReviewDecisionVerdict,
    ) -> Self {
        match decision {
            ReviewDecisionVerdict::Confirmed => Self::TruePositive,
            ReviewDecisionVerdict::RejectedFalsePositive => Self::FalsePositive,
            ReviewDecisionVerdict::NeedsReview => Self::NeedsReview,
            ReviewDecisionVerdict::AcceptedRisk => Self::ByDesign,
            ReviewDecisionVerdict::Suppressed => Self::Suppressed,
            ReviewDecisionVerdict::Deferred => Self::Deferred,
        }
    }

    pub(in crate::findings) fn as_export_str(self) -> &'static str {
        match self {
            Self::TruePositive => "tp",
            Self::FalsePositive => "fp",
            Self::NeedsReview => "needs_review",
            Self::ByDesign => "by_design",
            Self::Suppressed => "suppressed",
            Self::Deferred => "deferred",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingReviewCompletenessFilter {
    Open,
    Complete,
}

impl FindingReviewCompletenessFilter {
    pub fn from_input(value: &str) -> Result<Self> {
        match value.trim() {
            "open" | "pending" => Ok(Self::Open),
            "complete" | "completed" | "closed" => Ok(Self::Complete),
            other => anyhow::bail!("unknown findings:list completeness filter {other:?}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingLifecycleStatusFilter {
    Candidate,
    Seen,
    Suppressed,
    Snoozed,
    RuntimeVerified,
    RuntimeNotReproduced,
    VerificationBuildFailed,
    VerificationInfraError,
    VerificationUnsupported,
    NeedsDetail,
    VerifiedStatic,
    StaticallyRejected,
    NeedsRuntimeEvidence,
    StaticallySupported,
}

impl FindingLifecycleStatusFilter {
    pub fn from_input(value: &str) -> Result<Self> {
        match normalize_lifecycle_status(value).as_str() {
            "candidate" => Ok(Self::Candidate),
            "seen" => Ok(Self::Seen),
            "suppressed" => Ok(Self::Suppressed),
            "snoozed" | "deferred" => Ok(Self::Snoozed),
            "runtimeverified" | "executionconfirmed" => Ok(Self::RuntimeVerified),
            "runtimenotreproduced" => Ok(Self::RuntimeNotReproduced),
            "verificationbuildfailed" => Ok(Self::VerificationBuildFailed),
            "verificationinfraerror" => Ok(Self::VerificationInfraError),
            "verificationunsupported" => Ok(Self::VerificationUnsupported),
            "needsdetail" => Ok(Self::NeedsDetail),
            "verifiedstatic" | "staticallyconfirmed" => Ok(Self::VerifiedStatic),
            "staticallyrejected" => Ok(Self::StaticallyRejected),
            "needsruntimeevidence" => Ok(Self::NeedsRuntimeEvidence),
            "staticallysupported" => Ok(Self::StaticallySupported),
            other => anyhow::bail!("unknown findings:list lifecycle status filter {other:?}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Seen => "seen",
            Self::Suppressed => "suppressed",
            Self::Snoozed => "snoozed",
            Self::RuntimeVerified => "runtime_verified",
            Self::RuntimeNotReproduced => "runtime_not_reproduced",
            Self::VerificationBuildFailed => "verification_build_failed",
            Self::VerificationInfraError => "verification_infra_error",
            Self::VerificationUnsupported => "verification_unsupported",
            Self::NeedsDetail => "needs_detail",
            Self::VerifiedStatic => "verified_static",
            Self::StaticallyRejected => "statically_rejected",
            Self::NeedsRuntimeEvidence => "needs_runtime_evidence",
            Self::StaticallySupported => "statically_supported",
        }
    }
}

fn normalize_lifecycle_status(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace(['_', '-', ' '], "")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingListFilter {
    pub severity: Vec<Severity>,
    pub verdict: Vec<FindingVerdictFilter>,
    pub triage_state: Vec<FindingTriageStateFilter>,
    pub completeness: Vec<FindingReviewCompletenessFilter>,
    pub lifecycle_status: Vec<FindingLifecycleStatusFilter>,
    /// Coarse proof/confidence bands. Empty = no filter. Distinct from
    /// `lifecycle_status` (granular) and `verdict` (triage decision).
    pub confidence: Vec<ProofConfidence>,
    pub name: Option<String>,
    pub text_terms: Vec<String>,
    pub file_path: Option<String>,
    pub run_id: Vec<String>,
    pub revision_sha: Vec<String>,
    pub branch: Vec<String>,
    pub dirty: Option<bool>,
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
            completeness: Vec::new(),
            lifecycle_status: Vec::new(),
            confidence: Vec::new(),
            name: None,
            text_terms: Vec::new(),
            file_path: None,
            run_id: Vec::new(),
            revision_sha: Vec::new(),
            branch: Vec::new(),
            dirty: None,
            vuln_source: Vec::new(),
            limit: 50,
        }
    }
}
