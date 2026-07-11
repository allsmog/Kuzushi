//! Persisted per-task wall-clock durations, used to estimate how long a
//! running task has left (`~4m left` in the ambient progress chip). One
//! JSON file per workspace under `.kuzushi/`; keeps the last few runs per
//! task id and estimates with the median, so one anomalous run doesn't
//! skew the forecast.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const HISTORY_PER_TASK: usize = 5;
const FILE_NAME: &str = "task-durations.json";
const MAX_TASK_DURATION_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskDurationStore {
    root: Option<PathBuf>,
    history: BTreeMap<String, Vec<u64>>,
}

impl TaskDurationStore {
    /// Load the workspace's duration history; an absent or malformed file
    /// (or no target) yields an empty store rather than an error — ETA is
    /// advisory chrome, never a blocker.
    pub fn load(target: Option<&Path>) -> Self {
        let history = target
            .map(|root| read_history(root, &task_duration_file_path(root)))
            .transpose()
            .ok()
            .flatten()
            .unwrap_or_default();
        Self {
            root: target.map(Path::to_path_buf),
            history,
        }
    }

    /// In-memory store for tests and targetless sessions.
    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self {
            root: None,
            history: BTreeMap::new(),
        }
    }

    pub fn record_secs(&mut self, task_id: &str, secs: u64) -> anyhow::Result<()> {
        let runs = self.history.entry(task_id.to_string()).or_default();
        runs.push(secs);
        if runs.len() > HISTORY_PER_TASK {
            let excess = runs.len() - HISTORY_PER_TASK;
            runs.drain(..excess);
        }
        self.save()
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

    fn save(&self) -> anyhow::Result<()> {
        let Some(root) = self.root.as_deref() else {
            return Ok(());
        };
        let json = serde_json::to_string_pretty(&self.history)?;
        kuzushi_core::workspace::write_workspace_state_file(
            root,
            Path::new(kuzushi_core::workspace::KUZUSHI_STATE_DIR).join(FILE_NAME),
            json.as_bytes(),
        )?;
        Ok(())
    }
}

fn task_duration_file_path(root: &Path) -> PathBuf {
    kuzushi_core::workspace::workspace_state_root(root).join(FILE_NAME)
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

fn read_history(root: &Path, path: &Path) -> anyhow::Result<BTreeMap<String, Vec<u64>>> {
    let Some(text) =
        kuzushi_core::workspace::read_optional_workspace_text(root, path, MAX_TASK_DURATION_BYTES)?
    else {
        return Ok(BTreeMap::new());
    };
    serde_json::from_str(&text).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimates_median_of_recorded_runs() {
        let mut store = TaskDurationStore::in_memory();
        assert_eq!(store.estimate_secs("cpg:build"), None);
        for secs in [400, 100, 380] {
            store.record_secs("cpg:build", secs).unwrap();
        }
        assert_eq!(store.estimate_secs("cpg:build"), Some(380));
    }

    #[test]
    fn keeps_only_the_most_recent_runs() {
        let mut store = TaskDurationStore::in_memory();
        for secs in 1..=10 {
            store.record_secs("t", secs).unwrap();
        }
        // Last five runs are 6..=10; median is 8.
        assert_eq!(store.estimate_secs("t"), Some(8));
    }

    #[test]
    fn round_trips_through_the_workspace_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = TaskDurationStore::load(Some(dir.path()));
        store.record_secs("cpg:build", 379).unwrap();

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

    #[cfg(unix)]
    #[test]
    fn task_duration_writer_rejects_a_symlinked_artifact() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().expect("workspace");
        let mut outside = tempfile::NamedTempFile::new().expect("outside");
        std::io::Write::write_all(&mut outside, b"outside").expect("seed outside");
        std::fs::create_dir_all(kuzushi_core::workspace::workspace_state_root(
            workspace.path(),
        ))
        .expect("state dir");
        symlink(outside.path(), task_duration_file_path(workspace.path()))
            .expect("symlink artifact");
        let mut store = TaskDurationStore::load(Some(workspace.path()));

        let error = store
            .record_secs("cpg:build", 379)
            .expect_err("symlink must be rejected");

        assert!(error.to_string().contains("symlink"));
        assert_eq!(std::fs::read_to_string(outside.path()).unwrap(), "outside");
    }

    #[cfg(unix)]
    #[test]
    fn task_duration_reader_rejects_an_outside_symlink_without_loading_content() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().expect("workspace");
        let outside = tempfile::NamedTempFile::new().expect("outside");
        std::fs::write(outside.path(), r#"{"OUTSIDE_TASK_TOKEN":[999]}"#).unwrap();
        std::fs::create_dir_all(kuzushi_core::workspace::workspace_state_root(
            workspace.path(),
        ))
        .unwrap();
        symlink(outside.path(), task_duration_file_path(workspace.path())).unwrap();

        let store = TaskDurationStore::load(Some(workspace.path()));

        assert_eq!(store.estimate_secs("OUTSIDE_TASK_TOKEN"), None);
    }
}
