//! Candidates for the launch-time target picker. A bare interactive
//! `kuzushi` has no `--target`; rather than booting a hollow targetless
//! shell, the picker offers the operator an explicit choice — preserving
//! the "no silent cwd fallback" rule (PR #64) while keeping the front door
//! inside the guided journey.

use std::path::{Path, PathBuf};

/// Children of cwd shown at most — the picker is a launchpad, not a file
/// browser; anything else is one `target <path>` away.
const MAX_CHILD_CANDIDATES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetCandidate {
    pub path: PathBuf,
    /// Display label: `.` for cwd, the directory name for children.
    pub label: String,
    pub hint: &'static str,
}

/// cwd first, then child directories that look like engagement targets —
/// previous kuzushi targets (`.kuzushi/`) ahead of plain git repos, each
/// group alphabetical.
pub fn discover_target_candidates(cwd: &Path) -> Vec<TargetCandidate> {
    let mut candidates = vec![TargetCandidate {
        path: cwd.to_path_buf(),
        label: ".".to_string(),
        hint: directory_hint(cwd, "current directory"),
    }];
    candidates.extend(child_candidates(cwd));
    candidates
}

fn child_candidates(cwd: &Path) -> Vec<TargetCandidate> {
    let mut children: Vec<TargetCandidate> = candidate_child_dirs(cwd)
        .into_iter()
        .map(|path| child_candidate(path))
        .collect();
    children.sort_by(|a, b| {
        candidate_rank(a.hint)
            .cmp(&candidate_rank(b.hint))
            .then_with(|| a.label.cmp(&b.label))
    });
    children.truncate(MAX_CHILD_CANDIDATES);
    children
}

fn candidate_child_dirs(cwd: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(cwd) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir() && !is_hidden(path) && looks_like_target(path))
        .collect()
}

fn child_candidate(path: PathBuf) -> TargetCandidate {
    let label = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let hint = directory_hint(&path, "directory");
    TargetCandidate { path, label, hint }
}

fn directory_hint(path: &Path, fallback: &'static str) -> &'static str {
    if path.join(".kuzushi").is_dir() {
        "previous kuzushi target"
    } else if path.join(".git").exists() {
        "git repo"
    } else {
        fallback
    }
}

/// Previous targets sort ahead of plain repos.
fn candidate_rank(hint: &str) -> u8 {
    match hint {
        "previous kuzushi target" => 0,
        "git repo" => 1,
        _ => 2,
    }
}

fn looks_like_target(path: &Path) -> bool {
    path.join(".kuzushi").is_dir() || path.join(".git").exists()
}

fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .map(|name| name.to_string_lossy().starts_with('.'))
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch_dir(root: &Path, rel: &str) {
        std::fs::create_dir_all(root.join(rel)).expect("create dir");
    }

    #[test]
    fn cwd_is_always_the_first_candidate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let candidates = discover_target_candidates(dir.path());
        assert_eq!(candidates[0].label, ".");
        assert_eq!(candidates[0].path, dir.path());
        assert_eq!(candidates[0].hint, "current directory");
    }

    #[test]
    fn cwd_hint_recognizes_git_and_kuzushi_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        touch_dir(dir.path(), ".git");
        assert_eq!(discover_target_candidates(dir.path())[0].hint, "git repo");
        touch_dir(dir.path(), ".kuzushi");
        assert_eq!(
            discover_target_candidates(dir.path())[0].hint,
            "previous kuzushi target"
        );
    }

    #[test]
    fn children_list_repos_with_previous_targets_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        touch_dir(dir.path(), "zeta/.git");
        touch_dir(dir.path(), "alpha/.git");
        touch_dir(dir.path(), "mid/.kuzushi");
        touch_dir(dir.path(), "plain-dir");
        std::fs::write(dir.path().join("file.txt"), "x").expect("file");

        let labels: Vec<String> = discover_target_candidates(dir.path())
            .into_iter()
            .skip(1)
            .map(|candidate| candidate.label)
            .collect();
        assert_eq!(labels, vec!["mid", "alpha", "zeta"]);
    }

    #[test]
    fn hidden_dirs_and_non_repos_are_excluded() {
        let dir = tempfile::tempdir().expect("tempdir");
        touch_dir(dir.path(), ".hidden/.git");
        touch_dir(dir.path(), "not-a-repo");
        let candidates = discover_target_candidates(dir.path());
        assert_eq!(candidates.len(), 1, "only cwd remains: {candidates:?}");
    }
}
