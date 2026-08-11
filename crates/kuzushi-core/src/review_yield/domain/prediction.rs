use serde::Serialize;

/// One advisory review-yield score for one finding (design §19.1).
///
/// Leaf statistics are `Option` because a score that never reached a leaf has
/// none. They are never zero-filled: an absent number and a measured zero are
/// different claims, and only the leaf may supply the numbers.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewYieldSignal {
    pub model_id: String,
    pub task_id: String,
    pub feature_schema_id: String,
    pub leaf_id: Option<u16>,
    pub smoothed_positive_rate: Option<f64>,
    pub credible_interval_95: Option<(f64, f64)>,
    pub positive_count: Option<u32>,
    pub negative_count: Option<u32>,
    pub leaf_entropy_bits: Option<f64>,
    /// The hops taken, in order, up to and excluding the step that failed.
    pub decision_path: Vec<ReviewYieldPathStep>,
    pub eligibility: ReviewYieldEligibility,
}

/// How little the model knows about findings like this one, as the two numbers
/// the leaf measured: how mixed the prior outcomes were, and how many there
/// were. Both come from the same leaf, so they are carried together or not at
/// all.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LeafKnowledgeGap {
    pub entropy_bits: f64,
    pub support: u32,
}

impl ReviewYieldSignal {
    pub fn is_eligible(&self) -> bool {
        self.eligibility == ReviewYieldEligibility::Eligible
    }

    /// The knowledge-gap key, present only for an eligible score whose leaf
    /// supplied both statistics.
    ///
    /// An absent number is never filled in with a zero: zero entropy and zero
    /// support are both strong claims, and a row that cannot make them has no
    /// key rather than a flattering one.
    pub fn leaf_knowledge_gap(&self) -> Option<LeafKnowledgeGap> {
        if !self.is_eligible() {
            return None;
        }
        Some(LeafKnowledgeGap {
            entropy_bits: self.leaf_entropy_bits?,
            support: self.positive_count?.saturating_add(self.negative_count?),
        })
    }

    /// The decision path in the cross-language rendering both the Rust and the
    /// Python evaluator pin in `fixtures/parity/expected-scores.json`.
    pub fn rendered_path(&self) -> Vec<String> {
        self.decision_path.iter().map(ReviewYieldPathStep::render).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewYieldPathStep {
    pub node_id: u16,
    pub feature: String,
    pub taken: PathBranch,
}

impl ReviewYieldPathStep {
    pub fn render(&self) -> String {
        match &self.taken {
            PathBranch::Left { threshold } => self.numeric_render(*threshold, "left"),
            PathBranch::Right { threshold } => self.numeric_render(*threshold, "right"),
            PathBranch::Branch { value } => {
                format!("{}:{}=={}", self.node_id, self.feature, value)
            }
            PathBranch::Missing { direction } => {
                format!("{}:{}:missing-{}", self.node_id, self.feature, direction)
            }
        }
    }

    fn numeric_render(&self, threshold: f64, side: &str) -> String {
        format!(
            "{}:{}<={}:{}",
            self.node_id,
            self.feature,
            format_threshold(threshold),
            side
        )
    }
}

/// Renders a threshold the way the canonical JSON form writes it, so a path
/// string and the hashed artifact can never disagree about the same number.
pub fn format_threshold(threshold: f64) -> String {
    serde_json::Number::from_f64(threshold)
        .map(|number| number.to_string())
        .unwrap_or_else(|| "null".to_string())
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "branch", rename_all = "camelCase")]
pub enum PathBranch {
    Left { threshold: f64 },
    Right { threshold: f64 },
    Branch { value: String },
    Missing { direction: String },
}

/// Why a finding did or did not receive a score. Every load-time and
/// scoring-time failure lands on exactly one of these; there is no default and
/// no silent skip.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ReviewYieldEligibility {
    Eligible,
    /// Reserved for the operator-owned off switch (PR 7's config section).
    Disabled,
    /// Reserved for "review yield is on but no artifact is configured" (PR 7).
    NoModelConfigured,
    InvalidModelHash,
    UnsupportedModelSchema,
    FeatureSchemaMismatch,
    MissingRequiredFeature { feature: String },
    UnknownCategory { feature: String, value: String },
    InsufficientLeafSupport { support: u32 },
    OutOfDistribution { reason: String },
}

impl ReviewYieldEligibility {
    /// The serialized discriminant, for plain output and log lines.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::Disabled => "disabled",
            Self::NoModelConfigured => "noModelConfigured",
            Self::InvalidModelHash => "invalidModelHash",
            Self::UnsupportedModelSchema => "unsupportedModelSchema",
            Self::FeatureSchemaMismatch => "featureSchemaMismatch",
            Self::MissingRequiredFeature { .. } => "missingRequiredFeature",
            Self::UnknownCategory { .. } => "unknownCategory",
            Self::InsufficientLeafSupport { .. } => "insufficientLeafSupport",
            Self::OutOfDistribution { .. } => "outOfDistribution",
        }
    }

    /// A one-line operator-facing reason, empty when the kind says everything.
    pub fn detail(&self) -> String {
        match self {
            Self::MissingRequiredFeature { feature } => format!("feature {feature}"),
            Self::UnknownCategory { feature, value } => format!("{feature}={value}"),
            Self::InsufficientLeafSupport { support } => format!("support {support}"),
            Self::OutOfDistribution { reason } => reason.clone(),
            _ => String::new(),
        }
    }
}
