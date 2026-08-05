use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::label_policy::{FEATURE_SCHEMA_ID, LABEL_POLICY_ID, TASK_ID};

/// What the adjudication corpus of one target actually contains.
///
/// Every exclusion is counted rather than silently dropped: the difference
/// between `human_decision_events` and `eligible_identities` is always fully
/// explained by the `conflicted`, `no_eligible_label`, `missing_*` fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CensusReport {
    pub task_id: String,
    pub feature_schema_id: String,
    pub label_policy_id: String,
    pub decision_events: u64,
    pub human_decision_events: u64,
    pub by_author: BTreeMap<String, u64>,
    pub by_verdict: BTreeMap<String, u64>,
    pub by_dismiss_reason: BTreeMap<String, u64>,
    /// `tui_read_watermark` / `barrier_at_head` / `missing`, counted per
    /// human decision event.
    pub cutoff_quality: BTreeMap<String, u64>,
    pub adjudicated_identities: u64,
    pub eligible_identities: u64,
    pub positive: u64,
    pub negative: u64,
    pub conflicted: u64,
    /// Human decisions that moved a labeled identity into a policy outcome
    /// afterwards (informational; not a conflict).
    pub policy_transitions: u64,
    pub no_eligible_label: u64,
    pub missing_exact_cutoff: u64,
    pub missing_durable_identity: u64,
    pub missing_pre_cutoff_observation: u64,
    pub distinct_repositories: u64,
    pub distinct_tool_families: u64,
    pub distinct_rule_families: u64,
    pub distinct_language_families: u64,
    pub earliest_label_event_seq: Option<u64>,
    pub latest_label_event_seq: Option<u64>,
    pub event_log_head_seq: u64,
    pub projection_applied_seq: u64,
    pub projection_generation: u64,
}

impl Default for CensusReport {
    fn default() -> Self {
        Self {
            task_id: TASK_ID.to_string(),
            feature_schema_id: FEATURE_SCHEMA_ID.to_string(),
            label_policy_id: LABEL_POLICY_ID.to_string(),
            decision_events: 0,
            human_decision_events: 0,
            by_author: BTreeMap::new(),
            by_verdict: BTreeMap::new(),
            by_dismiss_reason: BTreeMap::new(),
            cutoff_quality: BTreeMap::new(),
            adjudicated_identities: 0,
            eligible_identities: 0,
            positive: 0,
            negative: 0,
            conflicted: 0,
            policy_transitions: 0,
            no_eligible_label: 0,
            missing_exact_cutoff: 0,
            missing_durable_identity: 0,
            missing_pre_cutoff_observation: 0,
            distinct_repositories: 0,
            distinct_tool_families: 0,
            distinct_rule_families: 0,
            distinct_language_families: 0,
            earliest_label_event_seq: None,
            latest_label_event_seq: None,
            event_log_head_seq: 0,
            projection_applied_seq: 0,
            projection_generation: 0,
        }
    }
}

impl CensusReport {
    pub fn bump(counter: &mut BTreeMap<String, u64>, key: &str) {
        *counter.entry(key.to_string()).or_insert(0) += 1;
    }
}
