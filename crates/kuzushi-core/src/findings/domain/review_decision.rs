use super::{FindingIdentityBasis, TriageAuthor, TriageOutcome, TriageVerdict};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecisionVerdict {
    Confirmed,
    /// Confirmed as real and queued for a fix. Terminal like `Confirmed`, but
    /// carries the operator intent that a patch is expected.
    ToFix,
    RejectedFalsePositive,
    Suppressed,
    Deferred,
    AcceptedRisk,
    #[default]
    NeedsReview,
}

impl ReviewDecisionVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::ToFix => "to_fix",
            Self::RejectedFalsePositive => "rejected_false_positive",
            Self::Suppressed => "suppressed",
            Self::Deferred => "deferred",
            Self::AcceptedRisk => "accepted_risk",
            Self::NeedsReview => "needs_review",
        }
    }

    pub fn from_triage_verdict(verdict: TriageVerdict) -> Self {
        match verdict {
            TriageVerdict::TruePositive => Self::Confirmed,
            TriageVerdict::FalsePositive => Self::RejectedFalsePositive,
            TriageVerdict::NeedsReview => Self::NeedsReview,
            TriageVerdict::ByDesign => Self::AcceptedRisk,
        }
    }

    pub fn to_triage_verdict(self) -> Option<TriageVerdict> {
        match self {
            Self::Confirmed | Self::ToFix => Some(TriageVerdict::TruePositive),
            Self::RejectedFalsePositive => Some(TriageVerdict::FalsePositive),
            Self::AcceptedRisk => Some(TriageVerdict::ByDesign),
            Self::NeedsReview => Some(TriageVerdict::NeedsReview),
            Self::Suppressed | Self::Deferred => None,
        }
    }

    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::NeedsReview)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "confirmed" => Self::Confirmed,
            "to_fix" => Self::ToFix,
            "rejected_false_positive" => Self::RejectedFalsePositive,
            "suppressed" => Self::Suppressed,
            "deferred" => Self::Deferred,
            "accepted_risk" => Self::AcceptedRisk,
            "needs_review" => Self::NeedsReview,
            _ => return None,
        })
    }
}

/// SARIF-ecosystem dismissal vocabulary (matches GitHub code scanning +
/// SARIF 2.1.0 suppression semantics). A dismissal is an operator asserting a
/// finding is not worth acting on; it never asserts the code is *fixed*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DismissReason {
    FalsePositive,
    AcceptableRisk,
    WontFix,
    UsedInTests,
    NoTimeToFix,
}

impl DismissReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FalsePositive => "false_positive",
            Self::AcceptableRisk => "acceptable_risk",
            Self::WontFix => "wont_fix",
            Self::UsedInTests => "used_in_tests",
            Self::NoTimeToFix => "no_time_to_fix",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value.trim() {
            "false_positive" | "false-positive" | "fp" => Self::FalsePositive,
            "acceptable_risk" | "acceptable-risk" | "accepted_risk" => Self::AcceptableRisk,
            "wont_fix" | "wont-fix" | "will_not_fix" => Self::WontFix,
            "used_in_tests" | "used-in-tests" | "test" | "tests" => Self::UsedInTests,
            "no_time_to_fix" | "no-time-to-fix" | "defer" => Self::NoTimeToFix,
            _ => return None,
        })
    }

    /// Back-compat verdict mapping so existing projections/filters keep working.
    pub fn as_review_verdict(self) -> ReviewDecisionVerdict {
        match self {
            Self::FalsePositive => ReviewDecisionVerdict::RejectedFalsePositive,
            Self::AcceptableRisk => ReviewDecisionVerdict::AcceptedRisk,
            Self::WontFix | Self::UsedInTests | Self::NoTimeToFix => {
                ReviewDecisionVerdict::Suppressed
            }
        }
    }

    /// Inverse of `as_review_verdict` for legacy events that carry only a
    /// verdict and no explicit dismissal reason.
    pub fn from_review_verdict(verdict: ReviewDecisionVerdict) -> Option<Self> {
        match verdict {
            ReviewDecisionVerdict::RejectedFalsePositive => Some(Self::FalsePositive),
            ReviewDecisionVerdict::AcceptedRisk => Some(Self::AcceptableRisk),
            ReviewDecisionVerdict::Suppressed => Some(Self::WontFix),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReviewDecision {
    pub verdict: ReviewDecisionVerdict,
    pub author: TriageAuthor,
    pub confidence: f32,
    pub rationale: String,
    /// Explicit dismissal reason when this decision dismisses the finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dismiss_reason: Option<DismissReason>,
    /// Resolved operator name (a labeling default like `"operator"`, not the
    /// `TriageAuthor` role enum). Present for human-driven dismissals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
}

impl ReviewDecision {
    pub fn from_triage(triage: &TriageOutcome, author: Option<TriageAuthor>) -> Self {
        Self {
            verdict: ReviewDecisionVerdict::from_triage_verdict(triage.verdict),
            author: author.unwrap_or(TriageAuthor::Auto),
            confidence: triage.confidence,
            rationale: triage.rationale_with_annotations(),
            dismiss_reason: None,
            actor: None,
        }
    }

    /// Builds a human dismissal decision from a reason + free-text note.
    pub fn dismissal(reason: DismissReason, note: &str, actor: &str) -> Self {
        Self {
            verdict: reason.as_review_verdict(),
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: note.to_string(),
            dismiss_reason: Some(reason),
            actor: Some(actor.to_string()),
        }
    }

    /// The effective dismissal reason for this decision: the explicit reason
    /// when present, else the canonical mapping from a legacy dismissal-style
    /// verdict. Returns `None` for non-dismissal decisions.
    pub fn effective_dismiss_reason(&self) -> Option<DismissReason> {
        self.dismiss_reason
            .or_else(|| DismissReason::from_review_verdict(self.verdict))
    }
}

/// Exact event-log provenance of a persisted review decision. `event_seq` is
/// the authoritative causal order (timestamps are display metadata and can
/// collide); `read_watermark` is the highest event sequence the decider had
/// observed before deciding, absent on legacy events that predate it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReviewDecisionProvenance {
    pub event_seq: u64,
    pub event_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_watermark: Option<u64>,
}

/// Why an automated review decision was copied across durable observations.
/// Human/imported decisions and finding-local automated decisions leave this
/// absent; propagation always names the source finding rows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReviewDecisionPropagation {
    pub basis: FindingIdentityBasis,
    pub source_finding_ids: Vec<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReviewDecisionRecord {
    pub id: i64,
    pub finding_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    pub decision: ReviewDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triage_verdict: Option<TriageVerdict>,
    pub created_at: String,
    /// `None` only for legacy projection rows whose decision event could not
    /// be recovered from the projected event store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ReviewDecisionProvenance>,
}
