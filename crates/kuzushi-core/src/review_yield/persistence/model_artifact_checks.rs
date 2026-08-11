use super::model_artifact::{ModelArtifactError, SUPPORTED_MODEL_SCHEMA_VERSION};
use super::model_artifact_raw::{
    RawCategoricalNode, RawLeafNode, RawMissingDirection, RawModel, RawNode, RawNumericNode,
};
use super::model_artifact_tree::check_tree_shape;
use crate::review_yield::domain::{
    collect_vocabularies, LeafStats, MissingDirection, ModelNode, ValidatedReviewYieldModel,
    FEATURE_SCHEMA_ID, MAX_CATEGORICAL_BRANCHES, MAX_MODEL_COUNT, MAX_MODEL_DEPTH, MAX_MODEL_NODES,
    MAX_MODEL_STRING_LEN, MODEL_KIND_DECISION_TREE, TASK_ID,
};

/// Turns a deserialized artifact into a model the evaluator may walk, or
/// explains exactly which bound it broke.
pub(crate) fn build_model(raw: RawModel) -> Result<ValidatedReviewYieldModel, ModelArtifactError> {
    check_identity(&raw)?;
    check_strings(&raw)?;
    check_training(&raw)?;
    check_scalars(&raw)?;
    let nodes = convert_nodes(&raw.nodes)?;
    let depth = check_tree_shape(&nodes)?;
    Ok(ValidatedReviewYieldModel {
        model_id: raw.model_id,
        task_id: raw.task_id,
        feature_schema_id: raw.feature_schema_id,
        label_policy_id: raw.label_policy_id,
        minimum_leaf_support: raw.eligibility.minimum_leaf_support,
        maximum_unknown_categories: raw.eligibility.maximum_unknown_categories,
        depth,
        vocabularies: collect_vocabularies(&nodes),
        nodes,
    })
}

/// The three identifiers that decide whether this build may evaluate the model
/// at all: what it predicts, how it predicts it, and what it reads.
fn check_identity(raw: &RawModel) -> Result<(), ModelArtifactError> {
    if raw.feature_schema_id != FEATURE_SCHEMA_ID {
        return Err(ModelArtifactError::FeatureSchemaMismatch {
            found: raw.feature_schema_id.clone(),
            expected: FEATURE_SCHEMA_ID.to_string(),
        });
    }
    if raw.task_id != TASK_ID {
        return Err(shape(format!("taskId {} is not {TASK_ID}", raw.task_id)));
    }
    if raw.model_kind != MODEL_KIND_DECISION_TREE {
        return Err(shape(format!(
            "modelKind {} is not {MODEL_KIND_DECISION_TREE}",
            raw.model_kind
        )));
    }
    Ok(())
}

fn check_strings(raw: &RawModel) -> Result<(), ModelArtifactError> {
    for (label, value) in artifact_strings(raw) {
        bounded_string(label, value)?;
    }
    Ok(())
}

fn artifact_strings(raw: &RawModel) -> Vec<(&'static str, &str)> {
    let mut strings = vec![
        ("modelId", raw.model_id.as_str()),
        ("modelKind", raw.model_kind.as_str()),
        ("taskId", raw.task_id.as_str()),
        ("featureSchemaId", raw.feature_schema_id.as_str()),
        ("labelPolicyId", raw.label_policy_id.as_str()),
        ("training.criterion", raw.training.criterion.as_str()),
        ("training.datasetDigest", raw.training.dataset_digest.as_str()),
    ];
    strings.extend(raw.nodes.iter().flat_map(node_strings));
    strings
}

fn node_strings(node: &RawNode) -> Vec<(&'static str, &str)> {
    match node {
        RawNode::Numeric(numeric) => vec![("node.feature", numeric.feature.as_str())],
        RawNode::Categorical(categorical) => {
            std::iter::once(("node.feature", categorical.feature.as_str()))
                .chain(
                    categorical
                        .branches
                        .keys()
                        .map(|key| ("node.branch", key.as_str())),
                )
                .collect()
        }
        RawNode::Leaf(_) => Vec::new(),
    }
}

/// Every artifact string is short printable ASCII, which is what keeps the
/// canonical JSON form free of escape sequences Python and Rust could render
/// differently.
fn bounded_string(label: &str, value: &str) -> Result<(), ModelArtifactError> {
    if value.is_empty() || value.len() > MAX_MODEL_STRING_LEN {
        return Err(bounds(format!(
            "{label} length {} is outside 1..={MAX_MODEL_STRING_LEN}",
            value.len()
        )));
    }
    if !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err(bounds(format!("{label} is not printable ASCII")));
    }
    Ok(())
}

/// The training block must describe a run this build could have produced: a
/// depth deeper than the evaluator walks would make the artifact self-
/// contradictory even if every node happened to fit.
fn check_training(raw: &RawModel) -> Result<(), ModelArtifactError> {
    if u64::from(raw.schema_version) != SUPPORTED_MODEL_SCHEMA_VERSION {
        return Err(shape(format!(
            "schemaVersion {} is not {SUPPORTED_MODEL_SCHEMA_VERSION}",
            raw.schema_version
        )));
    }
    let depth = usize::try_from(raw.training.max_depth).unwrap_or(usize::MAX);
    if !(1..=MAX_MODEL_DEPTH).contains(&depth) {
        return Err(bounds(format!(
            "training.maxDepth {depth} is outside 1..={MAX_MODEL_DEPTH}"
        )));
    }
    if raw.training.min_samples_leaf < 1 {
        return Err(bounds("training.minSamplesLeaf must be at least 1".into()));
    }
    Ok(())
}

fn check_scalars(raw: &RawModel) -> Result<(), ModelArtifactError> {
    unit_interval("displayBands.highMinimum", raw.display_bands.high_minimum)?;
    unit_interval("displayBands.mediumMinimum", raw.display_bands.medium_minimum)?;
    unit_interval("evaluation.brier", raw.evaluation.brier)?;
    unit_interval("evaluation.prAuc", raw.evaluation.pr_auc)?;
    unit_interval("evaluation.precisionAt20", raw.evaluation.precision_at20)?;
    unit_interval("evaluation.recallAt20", raw.evaluation.recall_at20)?;
    if raw.eligibility.minimum_leaf_support < 1 {
        return Err(bounds("eligibility.minimumLeafSupport must be at least 1".into()));
    }
    Ok(())
}

fn unit_interval(label: &str, value: f64) -> Result<(), ModelArtifactError> {
    if !(0.0..=1.0).contains(&value) {
        return Err(bounds(format!("{label} {value} is outside 0.0..=1.0")));
    }
    Ok(())
}

fn convert_nodes(raw: &[RawNode]) -> Result<Vec<ModelNode>, ModelArtifactError> {
    if raw.is_empty() || raw.len() > MAX_MODEL_NODES {
        return Err(bounds(format!(
            "nodes length {} is outside 1..={MAX_MODEL_NODES}",
            raw.len()
        )));
    }
    raw.iter()
        .enumerate()
        .map(|(index, node)| convert_node(index, node))
        .collect()
}

/// A node's declared `id` must equal its index, so a decision path and the
/// artifact's own numbering can never disagree.
fn convert_node(index: usize, raw: &RawNode) -> Result<ModelNode, ModelArtifactError> {
    if usize::from(raw.id()) != index {
        return Err(bounds(format!(
            "node at index {index} declares id {}",
            raw.id()
        )));
    }
    match raw {
        RawNode::Numeric(numeric) => numeric_node(numeric),
        RawNode::Categorical(categorical) => categorical_node(categorical),
        RawNode::Leaf(leaf) => leaf_node(leaf),
    }
}

fn numeric_node(raw: &RawNumericNode) -> Result<ModelNode, ModelArtifactError> {
    if !raw.threshold.is_finite() {
        return Err(bounds(format!(
            "node {} threshold is not finite",
            raw.feature
        )));
    }
    Ok(ModelNode::Numeric {
        feature: raw.feature.clone(),
        threshold: raw.threshold,
        left: raw.left,
        right: raw.right,
        missing_direction: direction(raw.missing_direction),
    })
}

/// A categorical node cannot route absence left or right: v1 artifacts carry no
/// "absent" branch key, so absence is reported instead of guessed.
fn categorical_node(raw: &RawCategoricalNode) -> Result<ModelNode, ModelArtifactError> {
    if raw.branches.is_empty() || raw.branches.len() > MAX_CATEGORICAL_BRANCHES {
        return Err(bounds(format!(
            "node {} has {} branches; the range is 1..={MAX_CATEGORICAL_BRANCHES}",
            raw.feature,
            raw.branches.len()
        )));
    }
    if !matches!(raw.missing_direction, RawMissingDirection::Ineligible) {
        return Err(bounds(format!(
            "categorical node {} must declare missingDirection ineligible",
            raw.feature
        )));
    }
    Ok(ModelNode::Categorical {
        feature: raw.feature.clone(),
        branches: raw.branches.clone(),
        missing_direction: MissingDirection::Ineligible,
    })
}

fn leaf_node(raw: &RawLeafNode) -> Result<ModelNode, ModelArtifactError> {
    check_leaf_numbers(
        raw.smoothed_positive_rate,
        raw.entropy_bits,
        raw.credible_interval_95,
    )?;
    check_leaf_counts(raw.positive_count, raw.negative_count)?;
    Ok(ModelNode::Leaf(LeafStats {
        positive_count: raw.positive_count,
        negative_count: raw.negative_count,
        smoothed_positive_rate: raw.smoothed_positive_rate,
        entropy_bits: raw.entropy_bits,
        credible_interval_95: raw.credible_interval_95,
    }))
}

fn check_leaf_numbers(
    rate: f64,
    entropy_bits: f64,
    interval: (f64, f64),
) -> Result<(), ModelArtifactError> {
    unit_interval("leaf.smoothedPositiveRate", rate)?;
    unit_interval("leaf.entropyBits", entropy_bits)?;
    unit_interval("leaf.credibleInterval95.low", interval.0)?;
    unit_interval("leaf.credibleInterval95.high", interval.1)?;
    if interval.0 > interval.1 {
        return Err(bounds(format!(
            "leaf.credibleInterval95 {:?} is inverted",
            interval
        )));
    }
    Ok(())
}

fn check_leaf_counts(positive: u32, negative: u32) -> Result<(), ModelArtifactError> {
    if positive > MAX_MODEL_COUNT || negative > MAX_MODEL_COUNT {
        return Err(bounds(format!(
            "leaf counts {positive}/{negative} exceed {MAX_MODEL_COUNT}"
        )));
    }
    Ok(())
}

fn direction(raw: RawMissingDirection) -> MissingDirection {
    match raw {
        RawMissingDirection::Left => MissingDirection::Left,
        RawMissingDirection::Right => MissingDirection::Right,
        RawMissingDirection::Ineligible => MissingDirection::Ineligible,
    }
}

fn bounds(message: String) -> ModelArtifactError {
    ModelArtifactError::Bounds(message)
}

fn shape(message: String) -> ModelArtifactError {
    ModelArtifactError::Shape(message)
}
