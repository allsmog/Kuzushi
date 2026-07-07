use super::{should_ignore_path, WorkspaceChange};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub fn coalesce_changes(changes: impl IntoIterator<Item = WorkspaceChange>) -> Vec<WorkspaceChange> {
    let mut state = CoalescedChanges::default();
    for change in changes {
        state.apply(change);
    }
    state.into_changes()
}

#[derive(Default)]
struct CoalescedChanges {
    files: BTreeMap<PathBuf, FileChange>,
    retained: Vec<WorkspaceChange>,
    full_snapshot: bool,
}

impl CoalescedChanges {
    fn apply(&mut self, change: WorkspaceChange) {
        if self.full_snapshot && full_snapshot_absorbs(&change) {
            return;
        }
        match change {
            WorkspaceChange::FileChanged(path) => self.record_file(path, FileChange::Changed),
            WorkspaceChange::FileDeleted(path) => self.record_file(path, FileChange::Deleted),
            WorkspaceChange::GitHeadChanged => self.record_git_head_changed(),
            other => self.retained.push(other),
        }
    }

    fn record_file(&mut self, path: PathBuf, change: FileChange) {
        if !should_ignore_path(&path) {
            self.files.insert(path, change);
        }
    }

    fn record_git_head_changed(&mut self) {
        self.full_snapshot = true;
        self.files.clear();
        self.retained.retain(|change| !full_snapshot_absorbs(change));
    }

    fn into_changes(mut self) -> Vec<WorkspaceChange> {
        if self.full_snapshot {
            self.retained.push(WorkspaceChange::GitHeadChanged);
        }
        self.retained
            .extend(self.files.into_iter().map(file_change_to_workspace_change));
        self.retained.sort();
        self.retained.dedup();
        self.retained
    }
}

fn full_snapshot_absorbs(change: &WorkspaceChange) -> bool {
    matches!(
        change,
        WorkspaceChange::FileChanged(_)
            | WorkspaceChange::FileDeleted(_)
            | WorkspaceChange::FileMoved { .. }
            | WorkspaceChange::ManifestChanged(_)
            | WorkspaceChange::LockfileChanged(_)
            | WorkspaceChange::GitIndexChanged
    )
}

fn file_change_to_workspace_change((path, change): (PathBuf, FileChange)) -> WorkspaceChange {
    match change {
        FileChange::Changed => WorkspaceChange::FileChanged(path),
        FileChange::Deleted => WorkspaceChange::FileDeleted(path),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileChange {
    Changed,
    Deleted,
}
