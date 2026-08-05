use anyhow::Result;

use super::extract_features::{
    extract_review_yield_features, FeatureCutoff, ReviewFeatureSource,
};
use super::label_selection::LabelSelection;
use crate::review_yield::domain::{
    example_id, identity_group, AnchorObservationRef, LabelEventRef, ReviewYieldFeaturesV1,
    RowQuality, TrainingExampleV1, FEATURE_SCHEMA_ID, LABEL_POLICY_ID, TASK_ID,
    TRAINING_EXAMPLE_SCHEMA_VERSION,
};
use crate::review_yield::persistence::{ObservationMeta, ReviewYieldProjectionReader};

pub struct RowInputs<'a> {
    pub identity_id: &'a str,
    pub repository_group: &'a str,
    pub selection: &'a LabelSelection,
    /// Every observation of this identity, ascending by event sequence.
    pub observations: &'a [ObservationMeta],
}

/// Builds one training example, or `None` when the identity has no snapshot at
/// or before the read cutoff (the caller counts that exclusion).
pub fn build_row(
    reader: &ReviewYieldProjectionReader,
    inputs: RowInputs<'_>,
) -> Result<Option<TrainingExampleV1>> {
    let cutoff = inputs.selection.cutoff;
    let history: Vec<ObservationMeta> = inputs
        .observations
        .iter()
        .filter(|observation| observation.created_seq <= cutoff)
        .cloned()
        .collect();
    let Some(anchor) = history.last().cloned() else {
        return Ok(None);
    };
    let source = ReviewFeatureSource {
        anchor_json: reader.observation_json(&anchor.observation_hash)?,
        history,
        reopened_count: reader.reopened_count_before(inputs.identity_id, cutoff)?,
    };
    let features = extract_review_yield_features(&source, FeatureCutoff::EventSeq(cutoff))?;
    ensure_anchor_precedes_cutoff_precedes_label(&anchor, inputs.selection)?;
    Ok(Some(example(&inputs, &anchor, features)))
}

/// The invariant the whole dataset rests on. A violation is a bug in the
/// selection or the projection, so it fails the export instead of quietly
/// dropping the row.
fn ensure_anchor_precedes_cutoff_precedes_label(
    anchor: &ObservationMeta,
    selection: &LabelSelection,
) -> Result<()> {
    anyhow::ensure!(
        anchor.created_seq <= selection.cutoff && selection.cutoff < selection.event_seq,
        "review-yield row is not event-bounded: anchor seq {}, cutoff {}, label seq {}",
        anchor.created_seq,
        selection.cutoff,
        selection.event_seq
    );
    Ok(())
}

fn example(
    inputs: &RowInputs<'_>,
    anchor: &ObservationMeta,
    features: ReviewYieldFeaturesV1,
) -> TrainingExampleV1 {
    let selection = inputs.selection;
    TrainingExampleV1 {
        schema_version: TRAINING_EXAMPLE_SCHEMA_VERSION,
        task_id: TASK_ID.to_string(),
        example_id: example_id(inputs.identity_id, &selection.event_hash),
        identity_group: identity_group(inputs.identity_id),
        repository_group: inputs.repository_group.to_string(),
        feature_schema_id: FEATURE_SCHEMA_ID.to_string(),
        label_policy_id: LABEL_POLICY_ID.to_string(),
        feature_cutoff_seq: selection.cutoff,
        anchor_observation: AnchorObservationRef {
            seq: anchor.created_seq,
            observation_hash: anchor.observation_hash.clone(),
            snapshot_hash: anchor.snapshot_hash.clone(),
        },
        label_event: LabelEventRef {
            seq: selection.event_seq,
            event_hash: selection.event_hash.clone(),
            verdict: selection.verdict.clone(),
            class: selection.class,
        },
        features,
        quality: RowQuality::durable(selection.cutoff_quality),
        label_conflict: false,
    }
}
