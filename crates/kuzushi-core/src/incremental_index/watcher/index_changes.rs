use super::*;
use sha2::{Digest, Sha256};
use std::process::Command;
use std::time::Duration;

const INDEX_READ_LIMIT: usize = 16 * 1024 * 1024;
const INDEX_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Git's index also stores mutable stat and monitor caches. Those do not
/// change staged membership, modes, object ids or merge stages.
pub(super) struct IndexChangeGuard {
    observed: Option<[u8; 32]>,
}

impl IndexChangeGuard {
    pub(super) fn capture(root: &Path) -> Self {
        Self {
            observed: staged_index_identity(root),
        }
    }

    pub(super) fn filter(&mut self, root: &Path, changes: &mut Vec<WorkspaceChange>) {
        if !changes.contains(&WorkspaceChange::GitIndexChanged) {
            return;
        }
        if !self.observe(staged_index_identity(root)) {
            changes.retain(|change| *change != WorkspaceChange::GitIndexChanged);
        }
    }

    fn observe(&mut self, current: Option<[u8; 32]>) -> bool {
        let changed = current.is_none() || self.observed != current;
        self.observed = current;
        changed
    }
}

fn staged_index_identity(root: &Path) -> Option<[u8; 32]> {
    read_staged_index_identity(root, INDEX_READ_LIMIT, INDEX_READ_TIMEOUT)
}

fn read_staged_index_identity(
    root: &Path,
    output_limit: usize,
    timeout: Duration,
) -> Option<[u8; 32]> {
    let mut command = Command::new("git");
    command
        .env("GIT_OPTIONAL_LOCKS", "0")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "--stage", "-z"]);
    let output = crate::bounded_subprocess::output_with_limits_and_control(
        &mut command,
        "Git staged inventory",
        output_limit,
        4096,
        timeout,
    )
    .ok()?;
    output
        .status
        .success()
        .then(|| Sha256::digest(output.stdout).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_index_identity_keeps_other_changes_and_unknown_reads_stay_visible() {
        let root = tempfile::tempdir().unwrap();
        let mut guard = IndexChangeGuard {
            observed: Some([1; 32]),
        };
        assert!(!guard.observe(Some([1; 32])));
        assert!(guard.observe(Some([2; 32])));
        assert!(guard.observe(None));
        assert!(guard.observe(None));
        assert!(guard.observe(Some([2; 32])));
        assert!(!guard.observe(Some([2; 32])));
        let mut changes = vec![WorkspaceChange::FileChanged("owned.txt".into())];
        guard.filter(root.path(), &mut changes);
        assert_eq!(
            changes,
            vec![WorkspaceChange::FileChanged("owned.txt".into())]
        );
    }

    fn git(root: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", args);
    }

    #[test]
    fn git_stat_refresh_does_not_change_staged_inventory_but_staging_does() {
        let root = tempfile::tempdir().unwrap();
        git(root.path(), &["init", "-q"]);
        std::fs::write(root.path().join("owned.txt"), "owned inert source\n").unwrap();
        git(root.path(), &["add", "owned.txt"]);
        assert!(read_staged_index_identity(root.path(), 1, INDEX_READ_TIMEOUT).is_none());
        assert!(
            read_staged_index_identity(root.path(), INDEX_READ_LIMIT, Duration::ZERO).is_none()
        );
        let mut guard = IndexChangeGuard::capture(root.path());
        let before = std::fs::read(root.path().join(".git/index")).unwrap();
        git(root.path(), &["update-index", "--untracked-cache"]);
        assert_ne!(
            std::fs::read(root.path().join(".git/index")).unwrap(),
            before
        );
        let mut changes = vec![
            WorkspaceChange::GitIndexChanged,
            WorkspaceChange::FileChanged("owned.txt".into()),
        ];
        guard.filter(root.path(), &mut changes);
        assert_eq!(
            changes,
            vec![WorkspaceChange::FileChanged("owned.txt".into())]
        );
        std::fs::write(root.path().join("added.txt"), "another owned inert file\n").unwrap();
        git(root.path(), &["add", "added.txt"]);
        let mut changes = vec![WorkspaceChange::GitIndexChanged];
        guard.filter(root.path(), &mut changes);
        assert_eq!(changes, vec![WorkspaceChange::GitIndexChanged]);
    }
}
