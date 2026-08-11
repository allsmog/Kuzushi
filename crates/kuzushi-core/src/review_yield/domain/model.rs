use std::collections::{BTreeMap, BTreeSet};

/// Hard bounds on a model artifact (design §23.7). They exist so a hostile or
/// corrupt file cannot make the evaluator allocate, recurse, or loop.
pub const MAX_MODEL_NODES: usize = 127;
pub const MAX_MODEL_DEPTH: usize = 6;
pub const MAX_MODEL_STRING_LEN: usize = 128;
pub const MAX_MODEL_FILE_BYTES: u64 = 256 * 1024;
pub const MAX_CATEGORICAL_BRANCHES: usize = 32;
pub const MAX_MODEL_COUNT: u32 = 1_000_000_000;

/// The only model kind this release evaluates.
pub const MODEL_KIND_DECISION_TREE: &str = "decision_tree";

/// The BLAKE3 domain separator for the model artifact digest. Python's
/// exporter uses the same string; see `experiments/review-yield/fixtures/parity`.
pub const MODEL_DIGEST_DOMAIN: &str = "kuzushi-review-yield-model-v1";

/// Where a node sends a feature that is absent from the vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MissingDirection {
    Left,
    Right,
    /// Absence is not routable: the finding is reported as ineligible.
    Ineligible,
}

impl MissingDirection {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Right => "right",
            Self::Ineligible => "ineligible",
        }
    }
}

/// The leaf statistics an eligible score reports verbatim. Nothing here is
/// recomputed at scoring time, so a score is exactly what training measured.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LeafStats {
    pub(crate) positive_count: u32,
    pub(crate) negative_count: u32,
    pub(crate) smoothed_positive_rate: f64,
    pub(crate) entropy_bits: f64,
    pub(crate) credible_interval_95: (f64, f64),
}

impl LeafStats {
    pub(crate) fn support(&self) -> u32 {
        self.positive_count.saturating_add(self.negative_count)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ModelNode {
    Numeric {
        feature: String,
        threshold: f64,
        left: u16,
        right: u16,
        missing_direction: MissingDirection,
    },
    Categorical {
        feature: String,
        branches: BTreeMap<String, u16>,
        missing_direction: MissingDirection,
    },
    Leaf(LeafStats),
}

impl ModelNode {
    /// The feature this node splits on, or `None` for a leaf.
    pub(crate) fn feature(&self) -> Option<&str> {
        match self {
            Self::Numeric { feature, .. } | Self::Categorical { feature, .. } => Some(feature),
            Self::Leaf(_) => None,
        }
    }

    pub(crate) fn missing_direction(&self) -> MissingDirection {
        match self {
            Self::Numeric {
                missing_direction, ..
            }
            | Self::Categorical {
                missing_direction, ..
            } => *missing_direction,
            Self::Leaf(_) => MissingDirection::Ineligible,
        }
    }

    /// Distinct child indices. A categorical node may route several branch keys
    /// to the same child (one-vs-rest expansion), which is not a shared child.
    pub(crate) fn children(&self) -> BTreeSet<u16> {
        match self {
            Self::Numeric { left, right, .. } => BTreeSet::from([*left, *right]),
            Self::Categorical { branches, .. } => branches.values().copied().collect(),
            Self::Leaf(_) => BTreeSet::new(),
        }
    }
}

/// A model artifact that passed every load-time check in
/// `persistence::model_artifact`. Its fields are private and there is no public
/// constructor, so an unchecked artifact cannot reach the evaluator.
#[derive(Debug, Clone)]
pub struct ValidatedReviewYieldModel {
    pub(crate) model_id: String,
    pub(crate) task_id: String,
    pub(crate) feature_schema_id: String,
    pub(crate) label_policy_id: String,
    pub(crate) minimum_leaf_support: u32,
    pub(crate) maximum_unknown_categories: u32,
    pub(crate) depth: usize,
    pub(crate) nodes: Vec<ModelNode>,
    pub(crate) vocabularies: BTreeMap<String, BTreeSet<String>>,
}

impl ValidatedReviewYieldModel {
    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn feature_schema_id(&self) -> &str {
        &self.feature_schema_id
    }

    pub fn label_policy_id(&self) -> &str {
        &self.label_policy_id
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Longest root-to-leaf edge count measured while checking the tree shape.
    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn minimum_leaf_support(&self) -> u32 {
        self.minimum_leaf_support
    }

    pub fn maximum_unknown_categories(&self) -> u32 {
        self.maximum_unknown_categories
    }

    /// Node by index. Indices come only from `children()` of a node in this
    /// same model, and the loader proved every one of them is in bounds.
    pub(crate) fn node(&self, index: u16) -> &ModelNode {
        &self.nodes[usize::from(index)]
    }

    /// The training vocabulary of every categorical feature the tree splits on,
    /// unioned across the nodes that split on it.
    pub(crate) fn vocabularies(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.vocabularies
    }
}

/// Collects the categorical vocabulary of every splitting feature.
pub(crate) fn collect_vocabularies(nodes: &[ModelNode]) -> BTreeMap<String, BTreeSet<String>> {
    let mut vocabularies: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for node in nodes {
        let ModelNode::Categorical {
            feature, branches, ..
        } = node
        else {
            continue;
        };
        let entry = vocabularies.entry(feature.clone()).or_default();
        entry.extend(branches.keys().cloned());
    }
    vocabularies
}
