use serde::{Deserialize, Serialize};

use crate::findings::ReviewDecisionVerdict;

/// Task the exported examples describe: predict the human review outcome of a
/// finding from evidence that already existed when the reviewer opened it.
pub const TASK_ID: &str = "review_yield_predecision_v1";
pub const FEATURE_SCHEMA_ID: &str = "kuzushi-review-yield-features-v1";
pub const LABEL_POLICY_ID: &str = "kuzushi-review-yield-labels-v1";
pub const TRAINING_EXAMPLE_SCHEMA_VERSION: u32 = 1;
pub const DATASET_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Binary label class of a single review decision under the v1 policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelClass {
    Positive,
    Negative,
    /// A policy outcome (risk accepted, suppressed, deferred, still open).
    /// Never a training label: it records what the team chose to do, not
    /// whether the finding was real.
    Excluded,
}

impl LabelClass {
    /// `Some(1)` for positive, `Some(0)` for negative, `None` when the verdict
    /// carries no evidence about the finding being real.
    pub fn binary_code(self) -> Option<u8> {
        match self {
            Self::Positive => Some(1),
            Self::Negative => Some(0),
            Self::Excluded => None,
        }
    }
}

/// Maps a review verdict onto the v1 label class.
///
/// Deliberately does not reuse `ReviewDecisionVerdict::is_terminal()`:
/// terminality is a workflow property (`accepted_risk` and `suppressed` are
/// terminal but say nothing about ground truth), and the label policy must not
/// drift when the workflow enum changes.
pub fn label_class(verdict: ReviewDecisionVerdict) -> LabelClass {
    match verdict {
        ReviewDecisionVerdict::Confirmed | ReviewDecisionVerdict::ToFix => LabelClass::Positive,
        ReviewDecisionVerdict::RejectedFalsePositive => LabelClass::Negative,
        ReviewDecisionVerdict::Suppressed
        | ReviewDecisionVerdict::Deferred
        | ReviewDecisionVerdict::AcceptedRisk
        | ReviewDecisionVerdict::NeedsReview => LabelClass::Excluded,
    }
}

/// Author buckets used by the census.
///
/// `review_decisions.author` is not enum-constrained — the projection falls
/// back to the raw event actor string — so unrecognized authors bucket as
/// `other` and are excluded. They are never silently treated as `human`.
pub fn author_bucket(author: &str) -> &'static str {
    match author.trim().to_ascii_lowercase().as_str() {
        "human" => "human",
        "auto" => "auto",
        "imported" => "imported",
        _ => "other",
    }
}

/// True only for the bucket whose decisions may carry a training label.
pub fn is_human_author(author: &str) -> bool {
    author_bucket(author) == "human"
}

/// How trustworthy the recorded read cutoff of a decision is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CutoffQuality {
    /// The decider carried a genuinely stale read cutoff: strictly more than
    /// one event separates what they had read from the decision they wrote.
    /// Only the shell's stale-frame path produces this.
    TuiReadWatermark,
    /// The read cutoff sits exactly one event below the decision. The write
    /// barrier guarantees the decider had seen everything up to that point;
    /// a freshly refreshed shell frame also lands here, so this claims only
    /// the weaker barrier semantics, never "the operator read this frame".
    BarrierAtHead,
    /// No usable cutoff: absent provenance, absent read cutoff, or a cutoff at
    /// or after the decision itself (which could include the decision's own
    /// effects). Ineligible for export.
    Missing,
}

impl CutoffQuality {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TuiReadWatermark => "tui_read_watermark",
            Self::BarrierAtHead => "barrier_at_head",
            Self::Missing => "missing",
        }
    }

    pub fn is_eligible(self) -> bool {
        !matches!(self, Self::Missing)
    }
}

/// Classifies the read cutoff of a decision event. No stored marker separates
/// a shell read cutoff from a write-barrier cutoff, so the distinction is
/// derived from the distance to the decision event and nothing else.
pub fn classify_cutoff(read_watermark: Option<u64>, event_seq: u64) -> CutoffQuality {
    let Some(watermark) = read_watermark else {
        return CutoffQuality::Missing;
    };
    if watermark >= event_seq {
        return CutoffQuality::Missing;
    }
    if watermark + 1 == event_seq {
        return CutoffQuality::BarrierAtHead;
    }
    CutoffQuality::TuiReadWatermark
}

/// The label policy as it is recorded in a dataset manifest.
pub fn label_policy_manifest() -> serde_json::Value {
    serde_json::json!({
        "id": LABEL_POLICY_ID,
        "positive": ["confirmed", "to_fix"],
        "negative": ["rejected_false_positive"],
        "excluded": ["accepted_risk", "suppressed", "deferred", "needs_review"],
        "includedAuthors": ["human"],
        "excludedAuthors": ["auto", "imported", "other"],
        "identityRule": "one row per durable identity, first eligible human decision wins",
        "conflictRule": "identities with opposing human binary decisions are counted and excluded",
        "cutoffRule": "features come only from observations at or before the decision's read cutoff",
        "exportedCutoffQuality": ["tui_read_watermark", "barrier_at_head"],
    })
}
