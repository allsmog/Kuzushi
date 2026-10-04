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
            "fp" | "false_positive" | "safe" | "rejected_false_positive" => Ok(Self::FalsePositive),
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

    pub(in crate::findings) fn from_review_decision(decision: ReviewDecisionVerdict) -> Self {
        match decision {
            ReviewDecisionVerdict::Confirmed | ReviewDecisionVerdict::ToFix => Self::TruePositive,
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
    // Legacy states, matched on the presence of triage metadata.
    Untriaged,
    Triaged,
    /// Observation presence is independent of the human triage verdict.
    NotObserved,
    // Derived triage-lifecycle states, matched via `derive_triage_state` in the
    // store layer. `Open` = still being worked (no verdict yet, or "needs
    // review"); distinct from review-completeness `open` (`completeness:open`).
    Open,
    Reviewing,
    Confirmed,
    ToFix,
    Dismissed,
    Fixed,
    Removed,
}

impl FindingTriageStateFilter {
    pub fn from_input(value: &str) -> Result<Self> {
        match value.trim() {
            "new" | "untriaged" => Ok(Self::Untriaged),
            "triaged" | "classified" => Ok(Self::Triaged),
            "not_observed" | "not-observed" => Ok(Self::NotObserved),
            "open" | "working" | "pending" => Ok(Self::Open),
            "reviewing" | "in_review" | "in-review" | "review" => Ok(Self::Reviewing),
            "confirmed" => Ok(Self::Confirmed),
            "to_fix" | "to-fix" | "tofix" => Ok(Self::ToFix),
            "dismissed" | "dismiss" => Ok(Self::Dismissed),
            "fixed" => Ok(Self::Fixed),
            "removed" | "gone" => Ok(Self::Removed),
            other => anyhow::bail!("unknown findings:list state filter {other:?}"),
        }
    }

    /// True for states whose evaluation requires the derived triage lifecycle
    /// (and therefore the projected `stable_findings.current_status`).
    pub fn is_derived(self) -> bool {
        !matches!(self, Self::Untriaged | Self::Triaged | Self::NotObserved)
    }

    /// Whether a derived `FindingTriageState` satisfies this filter variant.
    pub fn matches_derived(self, derived: &FindingTriageState) -> bool {
        match self {
            Self::Open => matches!(derived, FindingTriageState::Open),
            Self::Reviewing => matches!(derived, FindingTriageState::Reviewing),
            Self::Confirmed => matches!(derived, FindingTriageState::Confirmed),
            Self::ToFix => matches!(derived, FindingTriageState::ToFix),
            Self::Dismissed => derived.is_dismissed(),
            Self::Fixed => matches!(derived, FindingTriageState::Fixed),
            Self::Removed => matches!(derived, FindingTriageState::Removed),
            Self::Untriaged | Self::Triaged | Self::NotObserved => false,
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
    /// Coarse proof/confidence bands (Confirmed/Likely/Unverified/Dismissed),
    /// derived from `static_proof_state` (+ verification/triage/suppression).
    /// Empty = no filter. Distinct from `lifecycle_status` (granular),
    /// `verdict` (triage decision), and `triage_band` (the model's
    /// self-reported triage confidence, bucketed).
    pub confidence: Vec<ProofConfidence>,
    /// Filter by triage-confidence band (bucketed `TriageOutcome.confidence`).
    /// Empty = no filter. Untriaged findings never match a triage band
    /// (honest — no fabricated confidence). Distinct from `confidence` (the
    /// proof/verification axis).
    pub triage_band: Vec<ConfidenceBand>,
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
            triage_band: Vec::new(),
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
