use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SemgrepRuleSynthesisReport {
    pub count: usize,
    pub validation_passed: usize,
    pub candidates: Vec<SemgrepCandidateRule>,
    pub deterministic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SemgrepCandidateRule {
    pub id: String,
    pub source_fingerprint: String,
    pub source_rule_id: String,
    pub source_location: String,
    pub languages: Vec<String>,
    pub severity: String,
    pub message: String,
    pub source_tokens: Vec<String>,
    pub sink_tokens: Vec<String>,
    pub guard_tokens: Vec<String>,
    pub disabled: bool,
    pub enabled: bool,
    pub ready_for_manual_enable: bool,
    pub disabled_reason: String,
    pub validation: SemgrepRuleValidation,
    pub rule_yaml: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SemgrepRuleValidation {
    pub passed: bool,
    pub positive_fixtures: usize,
    pub positive_matches: usize,
    pub negative_fixtures: usize,
    pub negative_matches: usize,
    pub missing_positive_fixtures: Vec<String>,
    pub unexpected_negative_matches: Vec<String>,
}

impl SemgrepRuleValidation {
    pub(crate) fn empty() -> Self {
        Self {
            passed: false,
            positive_fixtures: 0,
            positive_matches: 0,
            negative_fixtures: 0,
            negative_matches: 0,
            missing_positive_fixtures: Vec::new(),
            unexpected_negative_matches: Vec::new(),
        }
    }
}
