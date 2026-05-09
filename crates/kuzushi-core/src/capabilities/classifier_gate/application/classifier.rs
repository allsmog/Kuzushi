use super::*;

pub(crate) const CLASSIFIER_SYSTEM_PROMPT: &str = r#"You are Kuzushi's classifier gate. You see one
candidate finding from a SAST tool and decide whether it is plausibly a real, triggerable
vulnerability that an attacker can exploit with realistic input.

Return ONLY a JSON object matching:

{ "likely": bool, "score": 0.0..=1.0, "reason": "one sentence" }

Be calibrated, not generous. A score of 0.8 means you are 80% confident a deep auditor
would mark this true_positive. A score of 0.2 means you would expect false_positive.
Reserve scores above 0.9 for cases with obvious user-controlled input flowing into a
clear sink with no visible guard."#;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct ClassifierResponse {
    #[serde(default)]
    pub(crate) likely: bool,
    #[serde(default)]
    pub(crate) score: f32,
    /// The model's stated reason. Surfaced via the rationale on
    /// `skip_outcome` only — kept for forward-compat / log enrichment.
    #[serde(default)]
    pub(crate) reason: String,
}

pub struct LikelyVulnClassifier<'a> {
    pub(crate) runtime: &'a RoutedRuntime,
    pub(crate) cfg: ClassifierConfig,
    pub(crate) quantile: Mutex<QuantileEstimator>,
}
