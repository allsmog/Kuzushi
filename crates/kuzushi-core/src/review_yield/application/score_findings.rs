use crate::review_yield::domain::{
    FeatureLookup, FeatureValue, LeafStats, MissingDirection, ModelNode, PathBranch,
    ReviewYieldEligibility, ReviewYieldPathStep, ReviewYieldSignal, ValidatedReviewYieldModel,
    MAX_MODEL_DEPTH,
};

/// Scores one feature vector against a checked model (design §19.2).
///
/// Pure: no filesystem, clock, randomness, or database access, and no state
/// carried between calls. Bounded: the walk is a `for` loop over the depth
/// limit, so termination is structural rather than argued.
pub fn score_review_yield<F: FeatureLookup>(
    model: &ValidatedReviewYieldModel,
    features: &F,
) -> ReviewYieldSignal {
    match unknown_category_overflow(model, features) {
        Some(eligibility) => ineligible(model, eligibility, Vec::new()),
        None => walk(model, features),
    }
}

/// Counts categorical features whose value is outside the training vocabulary.
/// More than the artifact allows means the finding is off-distribution, and a
/// leaf rate learned elsewhere would not describe it.
fn unknown_category_overflow<F: FeatureLookup>(
    model: &ValidatedReviewYieldModel,
    features: &F,
) -> Option<ReviewYieldEligibility> {
    let unknown = model
        .vocabularies()
        .iter()
        .filter(|(name, vocabulary)| is_unknown_category(features, name, vocabulary))
        .count();
    let allowed = usize::try_from(model.maximum_unknown_categories()).unwrap_or(usize::MAX);
    if unknown <= allowed {
        return None;
    }
    Some(ReviewYieldEligibility::OutOfDistribution {
        reason: format!("{unknown} categorical values outside training vocabulary"),
    })
}

fn is_unknown_category<F: FeatureLookup>(
    features: &F,
    name: &str,
    vocabulary: &std::collections::BTreeSet<String>,
) -> bool {
    match features.feature(name) {
        Some(FeatureValue::Category(value)) => !vocabulary.contains(&value),
        _ => false,
    }
}

/// Descends from the root. `MAX_MODEL_DEPTH + 1` iterations cover the deepest
/// tree the loader accepts; falling out of the loop is unreachable for a
/// checked model and is reported rather than assumed away.
fn walk<F: FeatureLookup>(
    model: &ValidatedReviewYieldModel,
    features: &F,
) -> ReviewYieldSignal {
    let mut path = Vec::new();
    let mut index = 0u16;
    for _ in 0..=MAX_MODEL_DEPTH {
        let node = model.node(index);
        if let ModelNode::Leaf(stats) = node {
            return leaf_signal(model, stats, index, path);
        }
        match step(node, index, features) {
            Step::Stop(eligibility) => return ineligible(model, eligibility, path),
            Step::Descend { next, taken } => {
                path.push(taken);
                index = next;
            }
        }
    }
    let reason = "depth guard exceeded".to_string();
    ineligible(model, ReviewYieldEligibility::OutOfDistribution { reason }, path)
}

enum Step {
    Descend {
        next: u16,
        taken: ReviewYieldPathStep,
    },
    Stop(ReviewYieldEligibility),
}

fn step<F: FeatureLookup>(node: &ModelNode, id: u16, features: &F) -> Step {
    let Some(name) = node.feature() else {
        return Step::Stop(missing(node.feature().unwrap_or_default()));
    };
    match features.feature(name) {
        None => Step::Stop(missing(name)),
        Some(FeatureValue::Missing) => missing_step(node, id, name),
        Some(value) => typed_step(node, id, name, value),
    }
}

/// An absent feature follows the node's declared direction. `ineligible` is a
/// real answer: the model was never trained on absence at this split.
fn missing_step(node: &ModelNode, id: u16, name: &str) -> Step {
    let direction = node.missing_direction();
    let next = match (node, direction) {
        (ModelNode::Numeric { left, .. }, MissingDirection::Left) => *left,
        (ModelNode::Numeric { right, .. }, MissingDirection::Right) => *right,
        _ => return Step::Stop(missing(name)),
    };
    Step::Descend {
        next,
        taken: ReviewYieldPathStep {
            node_id: id,
            feature: name.to_string(),
            taken: PathBranch::Missing {
                direction: direction.as_str().to_string(),
            },
        },
    }
}

/// A value of the wrong shape for its node is not routable, so it stops the
/// walk instead of being coerced into a branch.
fn typed_step(node: &ModelNode, id: u16, name: &str, value: FeatureValue) -> Step {
    match (node, value) {
        (ModelNode::Numeric { .. }, FeatureValue::Number(number)) => {
            numeric_step(node, id, name, number)
        }
        (ModelNode::Numeric { .. }, FeatureValue::Boolean(flag)) => {
            numeric_step(node, id, name, f64::from(u8::from(flag)))
        }
        (ModelNode::Categorical { .. }, FeatureValue::Category(token)) => {
            categorical_step(node, id, name, &token)
        }
        (ModelNode::Categorical { .. }, FeatureValue::Boolean(flag)) => {
            categorical_step(node, id, name, if flag { "true" } else { "false" })
        }
        _ => Step::Stop(missing(name)),
    }
}

/// `value <= threshold` goes left. The boundary belongs to the left branch;
/// `fixtures/parity/expected-scores.json` pins it in both languages.
fn numeric_step(node: &ModelNode, id: u16, name: &str, value: f64) -> Step {
    let ModelNode::Numeric {
        threshold,
        left,
        right,
        ..
    } = node
    else {
        return Step::Stop(missing(name));
    };
    let goes_left = value <= *threshold;
    let taken = match goes_left {
        true => PathBranch::Left {
            threshold: *threshold,
        },
        false => PathBranch::Right {
            threshold: *threshold,
        },
    };
    Step::Descend {
        next: if goes_left { *left } else { *right },
        taken: path_step(id, name, taken),
    }
}

fn categorical_step(node: &ModelNode, id: u16, name: &str, token: &str) -> Step {
    let ModelNode::Categorical { branches, .. } = node else {
        return Step::Stop(missing(name));
    };
    let Some(next) = branches.get(token) else {
        return Step::Stop(ReviewYieldEligibility::UnknownCategory {
            feature: name.to_string(),
            value: token.to_string(),
        });
    };
    Step::Descend {
        next: *next,
        taken: path_step(
            id,
            name,
            PathBranch::Branch {
                value: token.to_string(),
            },
        ),
    }
}

fn path_step(id: u16, name: &str, taken: PathBranch) -> ReviewYieldPathStep {
    ReviewYieldPathStep {
        node_id: id,
        feature: name.to_string(),
        taken,
    }
}

fn missing(feature: &str) -> ReviewYieldEligibility {
    ReviewYieldEligibility::MissingRequiredFeature {
        feature: feature.to_string(),
    }
}

/// A leaf under the artifact's support floor still reports its statistics: the
/// operator sees the thin evidence rather than a blank.
fn leaf_signal(
    model: &ValidatedReviewYieldModel,
    stats: &LeafStats,
    leaf_id: u16,
    path: Vec<ReviewYieldPathStep>,
) -> ReviewYieldSignal {
    let support = stats.support();
    let eligibility = match support < model.minimum_leaf_support() {
        true => ReviewYieldEligibility::InsufficientLeafSupport { support },
        false => ReviewYieldEligibility::Eligible,
    };
    ReviewYieldSignal {
        leaf_id: Some(leaf_id),
        smoothed_positive_rate: Some(stats.smoothed_positive_rate),
        credible_interval_95: Some(stats.credible_interval_95),
        positive_count: Some(stats.positive_count),
        negative_count: Some(stats.negative_count),
        leaf_entropy_bits: Some(stats.entropy_bits),
        decision_path: path,
        eligibility,
        ..identity(model)
    }
}

fn ineligible(
    model: &ValidatedReviewYieldModel,
    eligibility: ReviewYieldEligibility,
    path: Vec<ReviewYieldPathStep>,
) -> ReviewYieldSignal {
    ReviewYieldSignal {
        decision_path: path,
        eligibility,
        ..identity(model)
    }
}

/// The model provenance every signal carries, with no leaf statistics.
fn identity(model: &ValidatedReviewYieldModel) -> ReviewYieldSignal {
    ReviewYieldSignal {
        model_id: model.model_id().to_string(),
        task_id: model.task_id().to_string(),
        feature_schema_id: model.feature_schema_id().to_string(),
        leaf_id: None,
        smoothed_positive_rate: None,
        credible_interval_95: None,
        positive_count: None,
        negative_count: None,
        leaf_entropy_bits: None,
        decision_path: Vec::new(),
        eligibility: ReviewYieldEligibility::Eligible,
    }
}
