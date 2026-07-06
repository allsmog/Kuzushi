use super::{TriageAuthor, TriageOutcome, TriageVerdict};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecisionVerdict {
    Confirmed,
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
            Self::Confirmed => Some(TriageVerdict::TruePositive),
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
            "rejected_false_positive" => Self::RejectedFalsePositive,
            "suppressed" => Self::Suppressed,
            "deferred" => Self::Deferred,
            "accepted_risk" => Self::AcceptedRisk,
            "needs_review" => Self::NeedsReview,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReviewDecision {
    pub verdict: ReviewDecisionVerdict,
    pub author: TriageAuthor,
    pub confidence: f32,
    pub rationale: String,
}

impl ReviewDecision {
    pub fn from_triage(triage: &TriageOutcome, author: Option<TriageAuthor>) -> Self {
        Self {
            verdict: ReviewDecisionVerdict::from_triage_verdict(triage.verdict),
            author: author.unwrap_or(TriageAuthor::Auto),
            confidence: triage.confidence,
            rationale: triage.rationale.clone(),
        }
    }
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
}
