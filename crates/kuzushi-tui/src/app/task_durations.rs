//! Persisted per-task wall-clock durations, used to estimate how long a
//! running task has left (`~4m left` in the ambient progress chip). One
//! JSON file per workspace under `.kuzushi/`; keeps the last few runs per
//! task id and estimates with the median, so one anomalous run doesn't
//! skew the forecast.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const HISTORY_PER_TASK: usize = 5;
const FILE_NAME: &str = "task-durations.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskDurationStore {
    path: Option<PathBuf>,
    history: BTreeMap<String, Vec<u64>>,
}

impl TaskDurationStore {
    /// Load the workspace's duration history; an absent or malformed file
    /// (or no target) yields an empty store rather than an error — ETA is
    /// advisory chrome, never a blocker.
    pub fn load(target: Option<&Path>) -> Self {
        let path = target.map(|root| root.join(".kuzushi").join(FILE_NAME));
        let history = path.as_deref().map(read_history).unwrap_or_default();
        Self { path, history }
    }

    /// In-memory store for tests and targetless sessions.
    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self {
            path: None,
            history: BTreeMap::new(),
        }
    }

    pub fn record_secs(&mut self, task_id: &str, secs: u64) {
        let runs = self.history.entry(task_id.to_string()).or_default();
        runs.push(secs);
        if runs.len() > HISTORY_PER_TASK {
            let excess = runs.len() - HISTORY_PER_TASK;
            runs.drain(..excess);
        }
        self.save();
    }

    /// Median of recorded runs, or `None` when this task has no history.
    pub fn estimate_secs(&self, task_id: &str) -> Option<u64> {
        let runs = self.history.get(task_id)?;
        if runs.is_empty() {
            return None;
        }
        let mut sorted = runs.clone();
        sorted.sort_unstable();
        Some(sorted[sorted.len() / 2])
    }

    fn save(&self) {
        let Some(path) = self.path.as_deref() else {
            return;
        };
        let Ok(json) = serde_json::to_string_pretty(&self.history) else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(path, json);
    }
}

/// `379` → `6m19s`, `42` → `42s`. Shared by the ambient chip and the
/// completion banners so durations read identically everywhere.
pub(crate) fn compact_secs(secs: u64) -> String {
    if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

fn read_history(path: &Path) -> BTreeMap<String, Vec<u64>> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimates_median_of_recorded_runs() {
        let mut store = TaskDurationStore::in_memory();
        assert_eq!(store.estimate_secs("cpg:build"), None);
        for secs in [400, 100, 380] {
            store.record_secs("cpg:build", secs);
        }
        assert_eq!(store.estimate_secs("cpg:build"), Some(380));
    }

    #[test]
    fn keeps_only_the_most_recent_runs() {
        let mut store = TaskDurationStore::in_memory();
        for secs in 1..=10 {
            store.record_secs("t", secs);
        }
        // Last five runs are 6..=10; median is 8.
        assert_eq!(store.estimate_secs("t"), Some(8));
    }

    #[test]
    fn round_trips_through_the_workspace_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = TaskDurationStore::load(Some(dir.path()));
        store.record_secs("cpg:build", 379);

        let reloaded = TaskDurationStore::load(Some(dir.path()));
        assert_eq!(reloaded.estimate_secs("cpg:build"), Some(379));
    }

    #[test]
    fn malformed_file_loads_as_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kuzushi = dir.path().join(".kuzushi");
        std::fs::create_dir_all(&kuzushi).unwrap();
        std::fs::write(kuzushi.join(FILE_NAME), "not json").unwrap();
        let store = TaskDurationStore::load(Some(dir.path()));
        assert_eq!(store.estimate_secs("anything"), None);
    }
}
