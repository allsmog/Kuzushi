use std::collections::BTreeMap;

use anyhow::Result;

use super::extract_features::{extract_review_yield_features, FeatureCutoff, ReviewFeatureSource};
use super::score_findings::score_review_yield;
use crate::review_yield::domain::{ReviewYieldSignal, ValidatedReviewYieldModel};
use crate::review_yield::persistence::{ObservationMeta, ReviewYieldProjectionReader};

/// One advisory score for one durable finding identity.
pub struct ScoredIdentity {
    pub identity_id: String,
    pub signal: ReviewYieldSignal,
}

/// Scores every current finding identity in the target.
///
/// The three reads happen up front — head snapshots, observation history, and
/// reopen counts — so the evaluator runs against in-memory data and the walk
/// never touches the database.
pub fn score_current_findings(
    reader: &ReviewYieldProjectionReader,
    model: &ValidatedReviewYieldModel,
) -> Result<Vec<ScoredIdentity>> {
    let heads = reader.head_snapshots()?;
    let history = reader.observation_index()?;
    let reopened = reader.reopened_counts()?;
    heads
        .into_iter()
        .map(|(identity_id, anchor_json)| {
            score_identity(model, identity_id, anchor_json, &history, &reopened)
        })
        .collect()
}

fn score_identity(
    model: &ValidatedReviewYieldModel,
    identity_id: String,
    anchor_json: String,
    history: &BTreeMap<String, Vec<ObservationMeta>>,
    reopened: &BTreeMap<String, u32>,
) -> Result<ScoredIdentity> {
    let source = ReviewFeatureSource {
        anchor_json,
        history: history.get(&identity_id).cloned().unwrap_or_default(),
        reopened_count: reopened.get(&identity_id).copied().unwrap_or(0),
    };
    let features = extract_review_yield_features(&source, FeatureCutoff::ProjectionHead)?;
    Ok(ScoredIdentity {
        identity_id,
        signal: score_review_yield(model, &features),
    })
}
