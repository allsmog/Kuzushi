use std::collections::BTreeMap;

use serde::Deserialize;

/// The on-disk artifact shape (design §18.1). Every struct denies unknown
/// fields, so a key this release does not understand is a load failure rather
/// than something silently ignored.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawModel {
    pub(crate) schema_version: u32,
    pub(crate) model_id: String,
    pub(crate) model_kind: String,
    pub(crate) task_id: String,
    pub(crate) feature_schema_id: String,
    pub(crate) label_policy_id: String,
    pub(crate) training: RawTraining,
    pub(crate) eligibility: RawEligibility,
    pub(crate) display_bands: RawDisplayBands,
    pub(crate) evaluation: RawEvaluation,
    pub(crate) nodes: Vec<RawNode>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawTraining {
    pub(crate) criterion: String,
    pub(crate) dataset_digest: String,
    pub(crate) max_depth: u32,
    pub(crate) min_samples_leaf: u32,
    /// Provenance only: recorded so a model can be retrained identically, and
    /// declared here so the key is required and covered by the digest.
    #[allow(dead_code)]
    pub(crate) random_seed: u64,
    #[allow(dead_code)]
    pub(crate) training_cutoff_seq: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawEligibility {
    pub(crate) minimum_leaf_support: u32,
    pub(crate) maximum_unknown_categories: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawDisplayBands {
    pub(crate) high_minimum: f64,
    pub(crate) medium_minimum: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawEvaluation {
    pub(crate) brier: f64,
    pub(crate) pr_auc: f64,
    pub(crate) precision_at20: f64,
    pub(crate) recall_at20: f64,
}

/// `nodeType` is the discriminant, so an unknown node kind fails to
/// deserialize instead of being treated as one of the known three.
#[derive(Debug, Deserialize)]
#[serde(tag = "nodeType", rename_all = "camelCase")]
pub(crate) enum RawNode {
    Numeric(RawNumericNode),
    Categorical(RawCategoricalNode),
    Leaf(RawLeafNode),
}

impl RawNode {
    pub(crate) fn id(&self) -> u16 {
        match self {
            Self::Numeric(node) => node.id,
            Self::Categorical(node) => node.id,
            Self::Leaf(node) => node.id,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawNumericNode {
    pub(crate) id: u16,
    pub(crate) feature: String,
    pub(crate) threshold: f64,
    pub(crate) left: u16,
    pub(crate) right: u16,
    pub(crate) missing_direction: RawMissingDirection,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawCategoricalNode {
    pub(crate) id: u16,
    pub(crate) feature: String,
    pub(crate) branches: BTreeMap<String, u16>,
    pub(crate) missing_direction: RawMissingDirection,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawLeafNode {
    pub(crate) id: u16,
    pub(crate) positive_count: u32,
    pub(crate) negative_count: u32,
    pub(crate) smoothed_positive_rate: f64,
    pub(crate) entropy_bits: f64,
    pub(crate) credible_interval_95: (f64, f64),
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RawMissingDirection {
    Left,
    Right,
    Ineligible,
}
