use serde::{Deserialize, Serialize};

use super::feature_schema::ReviewYieldFeaturesV1;
use super::label_policy::CutoffQuality;

/// The finding snapshot the features were read from. Both hashes are content
/// addresses, so a consumer can prove the row was derived from that exact
/// pre-cutoff state without holding the snapshot itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorObservationRef {
    pub seq: u64,
    pub observation_hash: String,
    pub snapshot_hash: String,
}

/// The human decision event that produced the label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelEventRef {
    pub seq: u64,
    pub event_hash: String,
    pub verdict: String,
    /// 1 = confirmed real, 0 = rejected false positive.
    pub class: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RowQuality {
    pub cutoff_quality: CutoffQuality,
    /// Always `durable`: rows without a durable identity are never exported.
    pub identity_quality: String,
    /// Always `passed`: the whitelist deserialization cannot read a forbidden
    /// field, and the export tests assert the serialized row proves it.
    pub forbidden_field_check: String,
}

impl RowQuality {
    pub fn durable(cutoff_quality: CutoffQuality) -> Self {
        Self {
            cutoff_quality,
            identity_quality: "durable".to_string(),
            forbidden_field_check: "passed".to_string(),
        }
    }
}

/// One exported training example: exactly one durable identity, one human
/// decision, and features frozen at the decider's read cutoff.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrainingExampleV1 {
    pub schema_version: u32,
    pub task_id: String,
    /// `blake3:<hex>` over (identity id, label event hash).
    pub example_id: String,
    /// Salted grouping key for the durable identity. Never the identity id.
    pub identity_group: String,
    /// Salted grouping key for the repository. Never a path, and never the raw
    /// workspace root fingerprint (which hashes a local absolute path).
    pub repository_group: String,
    pub feature_schema_id: String,
    pub label_policy_id: String,
    /// Highest event sequence the features may see.
    pub feature_cutoff_seq: u64,
    pub anchor_observation: AnchorObservationRef,
    pub label_event: LabelEventRef,
    pub features: ReviewYieldFeaturesV1,
    pub quality: RowQuality,
    /// Always false in an export — conflicted identities are counted in the
    /// census and excluded from the dataset.
    pub label_conflict: bool,
}
