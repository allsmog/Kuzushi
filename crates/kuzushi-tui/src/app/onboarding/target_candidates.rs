//! Candidates for the launch-time target picker. A bare interactive
//! `kuzushi` has no `--target`; rather than booting a hollow targetless
//! shell, the picker offers the operator an explicit choice — preserving
//! the "no silent cwd fallback" rule (PR #64) while keeping the front door
//! inside the guided journey.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use kuzushi_core::{NestedProjectKind, NestedProjectScope, NestedProjectScopeTree};

/// Children of cwd shown at most — the picker is a launchpad, not a file
/// browser; anything else is one `target <path>` away.
const MAX_CHILD_CANDIDATES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetCandidate {
    pub path: PathBuf,
    /// Display label: `.` for cwd, the directory name for children.
    pub label: String,
    pub hint: &'static str,
    pub scope: Option<TargetCandidateScope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetCandidateScope {
    pub id: String,
    pub kind: NestedProjectKind,
    pub rel_path: String,
}

/// cwd first, then child directories that look like engagement targets —
/// previous kuzushi targets (`.kuzushi/`) ahead of plain git repos, each
/// group alphabetical.
pub fn discover_target_candidates(cwd: &Path) -> Vec<TargetCandidate> {
    let scope_tree = kuzushi_core::discover_nested_project_scopes(cwd);
    let nested_scopes = nested_scope_candidates(cwd, &scope_tree);
    let nested_scope_paths = candidate_paths(&nested_scopes);
    let mut candidates = vec![TargetCandidate {
        path: cwd.to_path_buf(),
        label: ".".to_string(),
        hint: directory_hint(cwd, "current directory"),
        scope: scope_tree.root_scope().map(TargetCandidateScope::from),
    }];
    candidates.extend(nested_scopes);
    candidates.extend(child_candidates(cwd, &nested_scope_paths));
    candidates
}

fn child_candidates(cwd: &Path, excluded_paths: &BTreeSet<PathBuf>) -> Vec<TargetCandidate> {
    let mut children: Vec<TargetCandidate> = candidate_child_dirs(cwd)
        .into_iter()
        .filter(|path| !excluded_paths.contains(&normalized_candidate_path(path)))
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
    TargetCandidate {
        path,
        label,
        hint,
        scope: None,
    }
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
        "git submodule" => 1,
        "vendored root" => 2,
        "dependency root" => 3,
        "git repo" => 4,
        _ => 5,
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

fn candidate_paths(candidates: &[TargetCandidate]) -> BTreeSet<PathBuf> {
    candidates
        .iter()
        .map(|candidate| normalized_candidate_path(&candidate.path))
        .collect()
}

fn normalized_candidate_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn nested_scope_candidates(
    cwd: &Path,
    scope_tree: &NestedProjectScopeTree,
) -> Vec<TargetCandidate> {
    let mut candidates = scope_tree
        .non_root_scopes()
        .filter_map(|scope| nested_scope_candidate(cwd, scope))
        .collect::<Vec<_>>();
    candidates.sort_by(|a, b| {
        candidate_rank(a.hint)
            .cmp(&candidate_rank(b.hint))
            .then_with(|| a.label.cmp(&b.label))
    });
    candidates
}

fn nested_scope_candidate(cwd: &Path, scope: &NestedProjectScope) -> Option<TargetCandidate> {
    let path = scope.absolute_path(cwd);
    path.is_dir().then(|| TargetCandidate {
        path,
        label: scope.display_label(),
        hint: scope_kind_hint(scope.kind),
        scope: Some(TargetCandidateScope::from(scope)),
    })
}

fn scope_kind_hint(kind: NestedProjectKind) -> &'static str {
    match kind {
        NestedProjectKind::Root => "current directory",
        NestedProjectKind::Submodule => "git submodule",
        NestedProjectKind::VendoredRoot => "vendored root",
        NestedProjectKind::DependencyRoot => "dependency root",
    }
}

impl From<&NestedProjectScope> for TargetCandidateScope {
    fn from(scope: &NestedProjectScope) -> Self {
        Self {
            id: scope.id.clone(),
            kind: scope.kind,
            rel_path: scope.rel_path.clone(),
        }
    }
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
    fn gitmodules_add_nested_submodule_candidates() {
        let dir = tempfile::tempdir().expect("tempdir");
        touch_dir(dir.path(), "libs/parser/.git");
        touch_dir(dir.path(), "plain/.git");
        std::fs::write(
            dir.path().join(".gitmodules"),
            r#"
            [submodule "libs/parser"]
                path = libs/parser
                url = https://example.invalid/parser.git
            "#,
        )
        .expect("gitmodules");

        let candidates = discover_target_candidates(dir.path());

        let submodule = candidates
            .iter()
            .find(|candidate| candidate.label == "libs/parser")
            .expect("nested submodule candidate");
        assert_eq!(submodule.hint, "git submodule");
        assert_eq!(
            submodule.scope.as_ref().map(|scope| scope.id.as_str()),
            Some("submodule-libs-parser")
        );
        assert!(
            candidates
                .iter()
                .position(|candidate| candidate.label == "libs/parser")
                < candidates
                    .iter()
                    .position(|candidate| candidate.label == "plain")
        );
    }

    #[test]
    fn gitmodules_deduplicate_direct_child_submodules() {
        let dir = tempfile::tempdir().expect("tempdir");
        touch_dir(dir.path(), "api/.git");
        std::fs::write(
            dir.path().join(".gitmodules"),
            r#"
            [submodule "api"]
                path = api
            "#,
        )
        .expect("gitmodules");

        let candidates = discover_target_candidates(dir.path());
        let api = candidates
            .iter()
            .filter(|candidate| candidate.label == "api")
            .collect::<Vec<_>>();

        assert_eq!(api.len(), 1);
        assert_eq!(api[0].hint, "git submodule");
    }

    #[test]
    fn vendored_and_dependency_roots_are_picker_candidates() {
        let dir = tempfile::tempdir().expect("tempdir");
        touch_dir(dir.path(), "vendor");
        touch_dir(dir.path(), "node_modules");

        let candidates = discover_target_candidates(dir.path());

        let vendor = candidates
            .iter()
            .find(|candidate| candidate.label == "vendor")
            .expect("vendor candidate");
        assert_eq!(vendor.hint, "vendored root");
        assert_eq!(
            vendor.scope.as_ref().map(|scope| scope.kind),
            Some(NestedProjectKind::VendoredRoot)
        );
        let node_modules = candidates
            .iter()
            .find(|candidate| candidate.label == "node_modules")
            .expect("dependency candidate");
        assert_eq!(node_modules.hint, "dependency root");
        assert_eq!(
            node_modules.scope.as_ref().map(|scope| scope.kind),
            Some(NestedProjectKind::DependencyRoot)
        );
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
