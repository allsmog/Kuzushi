//! Candidates for the launch-time target picker. A bare interactive
//! `kuzushi` has no `--target`; rather than booting a hollow targetless
//! shell, the picker offers the operator an explicit choice — preserving
//! the "no silent cwd fallback" rule (PR #64) while keeping the front door
//! inside the guided journey.

use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use kuzushi_core::{NestedProjectKind, NestedProjectScope, NestedProjectScopeTree};

/// Children of cwd shown at most — the picker is a launchpad, not a file
/// browser; anything else is one `target <path>` away.
const MAX_CHILD_CANDIDATES: usize = 8;
const MAX_RECENT_CANDIDATES: usize = 8;
const MAX_TARGET_HISTORY: usize = 20;
const TARGET_HISTORY_FILE: &str = "target-history.json";

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
    discover_target_candidates_with_recent(cwd, &load_recent_target_paths())
}

pub(crate) fn immediate_target_candidate(cwd: &Path) -> TargetCandidate {
    TargetCandidate {
        path: cwd.to_path_buf(),
        label: ".".to_string(),
        hint: "current directory",
        scope: None,
    }
}

/// The already-bound target, shown first when the picker opens over an
/// active session so Enter re-confirms instead of silently rebinding to cwd.
pub(crate) fn bound_target_candidate(target: &Path) -> TargetCandidate {
    TargetCandidate {
        path: target.to_path_buf(),
        label: target
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| target.display().to_string()),
        hint: "current target",
        scope: None,
    }
}

fn discover_target_candidates_with_recent(
    cwd: &Path,
    recent_paths: &[PathBuf],
) -> Vec<TargetCandidate> {
    let scope_tree = kuzushi_core::load_nested_project_scopes(cwd).ok().flatten();
    let nested_scopes = scope_tree
        .as_ref()
        .map(|tree| nested_scope_candidates(cwd, tree))
        .unwrap_or_default();
    let nested_scope_paths = candidate_paths(&nested_scopes);
    let mut candidates = vec![TargetCandidate {
        path: cwd.to_path_buf(),
        label: ".".to_string(),
        hint: directory_hint(cwd, "current directory"),
        scope: scope_tree
            .as_ref()
            .and_then(NestedProjectScopeTree::root_scope)
            .map(TargetCandidateScope::from),
    }];
    candidates.extend(nested_scopes);
    candidates.extend(child_candidates(cwd, &nested_scope_paths));
    append_recent_candidates(&mut candidates, recent_paths);
    candidates
}

pub fn record_recent_target(path: &Path) -> Result<()> {
    if skip_real_target_history_for_tests() {
        return Ok(());
    }
    record_recent_target_at(&target_history_path()?, path)
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

fn append_recent_candidates(candidates: &mut Vec<TargetCandidate>, recent_paths: &[PathBuf]) {
    let mut seen = candidate_paths(candidates);
    let recent = recent_paths
        .iter()
        .filter_map(|path| recent_candidate(path, &mut seen))
        .take(MAX_RECENT_CANDIDATES)
        .collect::<Vec<_>>();
    candidates.extend(recent);
}

fn recent_candidate(path: &Path, seen: &mut BTreeSet<PathBuf>) -> Option<TargetCandidate> {
    if !path.is_dir() {
        return None;
    }
    let normalized = normalized_candidate_path(path);
    if !seen.insert(normalized) {
        return None;
    }
    Some(TargetCandidate {
        path: path.to_path_buf(),
        label: recent_target_label(path),
        hint: "recent target",
        scope: None,
    })
}

fn recent_target_label(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
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
        "recent target" => 1,
        "git submodule" => 2,
        "vendored root" => 3,
        "dependency root" => 4,
        "git repo" => 5,
        _ => 6,
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

fn load_recent_target_paths() -> Vec<PathBuf> {
    if skip_real_target_history_for_tests() {
        return Vec::new();
    }
    target_history_path()
        .ok()
        .and_then(|path| read_target_history(&path))
        .unwrap_or_default()
}

fn target_history_path() -> Result<PathBuf> {
    Ok(kuzushi_core::ConfigPaths::from_target(None)?
        .global_history_path()
        .with_file_name(TARGET_HISTORY_FILE))
}

fn read_target_history(path: &Path) -> Option<Vec<PathBuf>> {
    let raw = fs::read_to_string(path).ok()?;
    let entries = serde_json::from_str::<Vec<String>>(&raw).ok()?;
    Some(
        entries
            .into_iter()
            .map(PathBuf::from)
            .filter(|path| path.is_dir())
            .collect(),
    )
}

fn record_recent_target_at(history_path: &Path, target: &Path) -> Result<()> {
    let target = normalized_candidate_path(target);
    let mut entries = read_target_history(history_path).unwrap_or_default();
    entries.retain(|path| normalized_candidate_path(path) != target);
    entries.insert(0, target);
    entries.truncate(MAX_TARGET_HISTORY);
    if let Some(parent) = history_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(&history_strings(&entries))
        .context("Could not serialize target history")?;
    fs::write(history_path, body)
        .with_context(|| format!("Could not write {}", history_path.display()))
}

fn history_strings(entries: &[PathBuf]) -> Vec<String> {
    entries
        .iter()
        .map(|path| path.display().to_string())
        .collect()
}

fn skip_real_target_history_for_tests() -> bool {
    cfg!(test) && std::env::var_os("KUZUSHI_TUI_TEST_TARGET_HISTORY").is_none()
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
        NestedProjectKind::PackageRoot => "package root",
        NestedProjectKind::EntrypointCluster => "entrypoint cluster",
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
    fn recent_targets_from_other_cwds_are_listed() {
        let cwd = tempfile::tempdir().expect("cwd");
        let other = tempfile::tempdir().expect("other");
        touch_dir(other.path(), ".git");

        let labels: Vec<String> =
            discover_target_candidates_with_recent(cwd.path(), &[other.path().to_path_buf()])
                .into_iter()
                .map(|candidate| format!("{}:{}", candidate.label, candidate.hint))
                .collect();

        let other_label = other
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(labels.contains(&format!("{other_label}:recent target")));
    }

    #[test]
    fn recent_targets_dedupe_existing_candidates() {
        let cwd = tempfile::tempdir().expect("cwd");
        touch_dir(cwd.path(), "repo/.git");
        let repo = cwd.path().join("repo");

        let candidates = discover_target_candidates_with_recent(cwd.path(), &[repo]);
        let repo_rows = candidates
            .iter()
            .filter(|candidate| candidate.label == "repo")
            .count();

        assert_eq!(repo_rows, 1);
    }

    #[test]
    fn record_recent_target_moves_existing_entry_to_front() {
        let dir = tempfile::tempdir().expect("tempdir");
        let history_path = dir.path().join("target-history.json");
        touch_dir(dir.path(), "one/.git");
        touch_dir(dir.path(), "two/.git");

        record_recent_target_at(&history_path, &dir.path().join("one")).unwrap();
        record_recent_target_at(&history_path, &dir.path().join("two")).unwrap();
        record_recent_target_at(&history_path, &dir.path().join("one")).unwrap();

        let entries = read_target_history(&history_path).unwrap();
        assert_eq!(
            entries[0],
            normalized_candidate_path(&dir.path().join("one"))
        );
        assert_eq!(
            entries[1],
            normalized_candidate_path(&dir.path().join("two"))
        );
        assert_eq!(entries.len(), 2);
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
        let scope_tree = kuzushi_core::discover_and_save_nested_project_scopes(dir.path()).unwrap();
        let expected_scope_id = scope_tree
            .non_root_scopes()
            .find(|scope| scope.rel_path == "libs/parser")
            .expect("persisted submodule scope")
            .id
            .clone();

        let candidates = discover_target_candidates(dir.path());

        let submodule = candidates
            .iter()
            .find(|candidate| candidate.label == "libs/parser")
            .expect("nested submodule candidate");
        assert_eq!(submodule.hint, "git submodule");
        assert_eq!(
            submodule.scope.as_ref().map(|scope| scope.id.as_str()),
            Some(expected_scope_id.as_str())
        );
        assert!(expected_scope_id.starts_with("submodule-libs-parser-"));
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
        kuzushi_core::discover_and_save_nested_project_scopes(dir.path()).unwrap();

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
        kuzushi_core::discover_and_save_nested_project_scopes(dir.path()).unwrap();

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
