use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkItemKey {
    pub stable_id: String,
    pub content_hash: String,
}

impl WorkItemKey {
    pub fn new(stable_id: impl Into<String>, content_hash: impl Into<String>) -> Self {
        Self {
            stable_id: stable_id.into(),
            content_hash: content_hash.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkItem<I> {
    pub key: WorkItemKey,
    pub input: I,
}

impl<I> WorkItem<I> {
    pub fn new(key: WorkItemKey, input: I) -> Self {
        Self { key, input }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialFailurePolicy {
    CollectErrors,
    FailFast,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletedWorkItem<T> {
    pub key: WorkItemKey,
    pub value: T,
    #[serde(default)]
    pub skipped_from_checkpoint: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailedWorkItem {
    pub key: WorkItemKey,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FanoutOutcome<T> {
    pub completed: Vec<CompletedWorkItem<T>>,
    pub failed: Vec<FailedWorkItem>,
    pub skipped_from_checkpoint: Vec<WorkItemKey>,
    pub cost_usd: f64,
}

impl<T> Default for FanoutOutcome<T> {
    fn default() -> Self {
        Self {
            completed: Vec::new(),
            failed: Vec::new(),
            skipped_from_checkpoint: Vec::new(),
            cost_usd: 0.0,
        }
    }
}
