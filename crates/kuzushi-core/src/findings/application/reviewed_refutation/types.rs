use super::super::TriageAuthor;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct RefutationCohortKey {
    pub tool: String,
    pub rule_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_set_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReviewedRefutationPrior {
    pub key: RefutationCohortKey,
    pub emitted: usize,
    pub reviewed: usize,
    pub refuted: usize,
    pub shrunken_refutation_rate: f64,
    pub credible_interval_90: [f64; 2],
}

impl ReviewedRefutationPrior {
    pub fn prompt_note(&self) -> String {
        format!(
            "Historical human-reviewed refutation prior (advisory only; never suppress or decide this finding): {:.1}% shrunken ({}/{} reviewed refuted; {}/{} emitted reviewed; 90% credible interval {:.1}%–{:.1}%). Re-evaluate the current evidence independently.",
            self.shrunken_refutation_rate * 100.0,
            self.refuted,
            self.reviewed,
            self.reviewed,
            self.emitted,
            self.credible_interval_90[0] * 100.0,
            self.credible_interval_90[1] * 100.0,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RefutationCohortFact {
    pub finding_id: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    pub key: RefutationCohortKey,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RefutationPopulation {
    Human,
    Automatic,
    Imported,
}

impl RefutationPopulation {
    pub(super) fn from_author(author: TriageAuthor) -> Self {
        match author {
            TriageAuthor::Human => Self::Human,
            TriageAuthor::Auto => Self::Automatic,
            TriageAuthor::Imported => Self::Imported,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RefutationPopulationStats {
    pub population: RefutationPopulation,
    pub emitted: usize,
    pub reviewed: usize,
    pub refuted: usize,
    pub observed_refutation_rate: Option<f64>,
    pub weighted_reviewed: f64,
    pub weighted_refuted: f64,
    pub posterior_alpha: f64,
    pub posterior_beta: f64,
    pub shrunken_refutation_rate: f64,
    pub credible_interval_90: [f64; 2],
    pub undated_reviewed: usize,
}

impl RefutationPopulationStats {
    /// Advisory ordering/prompt value. It is intentionally not a decision or
    /// filter predicate.
    pub fn prior_context_rate(&self) -> f64 {
        self.shrunken_refutation_rate
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReviewedRefutationCohort {
    pub key: RefutationCohortKey,
    pub populations: Vec<RefutationPopulationStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReviewedRefutationReport {
    pub report_only: bool,
    pub prior: String,
    pub interval: String,
    pub decay_half_life_days: u32,
    pub as_of_unix: u64,
    pub emitted: usize,
    pub unmatched_decisions: usize,
    pub populations: Vec<RefutationPopulationStats>,
    pub cohorts: Vec<ReviewedRefutationCohort>,
    pub limitations: Vec<String>,
}
