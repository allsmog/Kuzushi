use std::collections::BTreeMap;

use anyhow::Result;

use super::extract_features::{extract_review_yield_features, FeatureCutoff, ReviewFeatureSource};
use super::score_findings::score_review_yield;
use crate::review_yield::domain::{
    feature_snapshot_hash, LeafKnowledgeGap, ReviewYieldSignal, ValidatedReviewYieldModel,
};
use crate::review_yield::persistence::{ObservationMeta, ReviewYieldProjectionReader};
use crate::workspace::WorkspaceTarget;

type Snapshots = BTreeMap<String, String>;
type History = BTreeMap<String, Vec<ObservationMeta>>;
type ReopenCounts = BTreeMap<String, u32>;

/// Why one queue row could not be scored. Each variant is a fact about the
/// stored record, not a stand-in for a score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnscorableReason {
    /// The finding has no durable identity, so no history can be joined to it.
    NoDurableIdentity,
    /// No snapshot of this identity is stored in the projection.
    NoStoredSnapshot,
    /// A snapshot exists but does not read back as a finding record.
    SnapshotUnreadable,
}

impl UnscorableReason {
    pub fn kind(self) -> &'static str {
        match self {
            Self::NoDurableIdentity => "noDurableIdentity",
            Self::NoStoredSnapshot => "noStoredSnapshot",
            Self::SnapshotUnreadable => "snapshotUnreadable",
        }
    }
}

/// One advisory score, positionally aligned with the queue it was asked about.
#[derive(Debug, Clone, PartialEq)]
pub enum ShadowQueueScore {
    Scored {
        signal: ReviewYieldSignal,
        feature_snapshot_hash: String,
    },
    Unscorable(UnscorableReason),
}

impl ShadowQueueScore {
    /// The discriminant a review session records. Eligibility details are left
    /// out: they can name a categorical feature value.
    pub fn eligibility_kind(&self) -> &'static str {
        match self {
            Self::Scored { signal, .. } => signal.eligibility.kind(),
            Self::Unscorable(reason) => reason.kind(),
        }
    }

    pub fn feature_snapshot_hash(&self) -> Option<&str> {
        match self {
            Self::Scored {
                feature_snapshot_hash,
                ..
            } => Some(feature_snapshot_hash),
            Self::Unscorable(_) => None,
        }
    }

    /// The advisory rate, present only for a fully eligible score. An
    /// ineligible row has no rate to offer, so callers cannot accidentally rank
    /// on one.
    pub fn eligible_rate(&self) -> Option<f64> {
        match self {
            Self::Scored { signal, .. } if signal.is_eligible() => signal.smoothed_positive_rate,
            _ => None,
        }
    }

    /// The knowledge-gap key, present only for a fully eligible score whose
    /// leaf reported both statistics. The same fail-closed shape as
    /// `eligible_rate`: a row without one cannot be ranked on it.
    pub fn eligible_knowledge_gap(&self) -> Option<LeafKnowledgeGap> {
        match self {
            Self::Scored { signal, .. } => signal.leaf_knowledge_gap(),
            Self::Unscorable(_) => None,
        }
    }
}

/// Scores a review queue without reordering it.
///
/// `identities` is the queue in the order the operator sees, one entry per row.
/// The three projection reads happen once up front, so a queue of any length
/// costs the same three queries and the evaluator then runs in memory.
/// The returned vector is positionally aligned with `identities` and is never
/// sorted: ordering is the caller's, and this function does not touch it.
pub fn score_review_queue_shadow(
    workspace: &WorkspaceTarget,
    identities: &[Option<String>],
    cutoff_seq: u64,
    model: &ValidatedReviewYieldModel,
) -> Result<Vec<ShadowQueueScore>> {
    let reader = ReviewYieldProjectionReader::open(workspace)?;
    let snapshots = reader.head_snapshots()?;
    let history = reader.observation_index()?;
    let reopened = reader.reopened_counts()?;
    Ok(identities
        .iter()
        .map(|identity| {
            let source = feature_source(identity.as_deref(), &snapshots, &history, &reopened);
            score_row(model, source, cutoff_seq)
        })
        .collect())
}

fn feature_source(
    identity: Option<&str>,
    snapshots: &Snapshots,
    history: &History,
    reopened: &ReopenCounts,
) -> Result<ReviewFeatureSource, UnscorableReason> {
    let identity = identity
        .filter(|value| !value.trim().is_empty())
        .ok_or(UnscorableReason::NoDurableIdentity)?;
    let anchor_json = snapshots
        .get(identity)
        .ok_or(UnscorableReason::NoStoredSnapshot)?;
    Ok(ReviewFeatureSource {
        anchor_json: anchor_json.clone(),
        history: history.get(identity).cloned().unwrap_or_default(),
        reopened_count: reopened.get(identity).copied().unwrap_or(0),
    })
}

fn score_row(
    model: &ValidatedReviewYieldModel,
    source: Result<ReviewFeatureSource, UnscorableReason>,
    cutoff_seq: u64,
) -> ShadowQueueScore {
    let scored = source.and_then(|source| {
        let features = extract_review_yield_features(&source, FeatureCutoff::EventSeq(cutoff_seq))
            .map_err(|_| UnscorableReason::SnapshotUnreadable)?;
        let hash =
            feature_snapshot_hash(&features).map_err(|_| UnscorableReason::SnapshotUnreadable)?;
        Ok(ShadowQueueScore::Scored {
            signal: score_review_yield(model, &features),
            feature_snapshot_hash: hash,
        })
    });
    scored.unwrap_or_else(ShadowQueueScore::Unscorable)
}
