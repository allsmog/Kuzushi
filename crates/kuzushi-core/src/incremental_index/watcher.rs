use super::{coalesce_changes, should_ignore_path, WorkspaceChange};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchScope {
    pub root: PathBuf,
    pub roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchEvent {
    Created(PathBuf),
    Modified(PathBuf),
    Deleted(PathBuf),
    Moved { from: PathBuf, to: PathBuf },
}

pub fn workspace_watch_scope(root: impl AsRef<Path>) -> WatchScope {
    let root = root.as_ref().to_path_buf();
    WatchScope {
        roots: vec![
            root.clone(),
            root.join(".git"),
            root.join(".kuzushi/house-rules"),
            root.join(".kuzushi/prompts"),
        ],
        root,
    }
}

pub fn classify_watcher_events(
    root: impl AsRef<Path>,
    events: impl IntoIterator<Item = WatchEvent>,
) -> Vec<WorkspaceChange> {
    let root = root.as_ref();
    coalesce_changes(
        events
            .into_iter()
            .flat_map(|event| classify_watcher_event(root, event)),
    )
}

pub fn classify_watcher_event(root: &Path, event: WatchEvent) -> Vec<WorkspaceChange> {
    match event {
        WatchEvent::Created(path) | WatchEvent::Modified(path) => {
            classify_existing_path(root, &path).into_iter().collect()
        }
        WatchEvent::Deleted(path) => classify_deleted_path(root, &path).into_iter().collect(),
        WatchEvent::Moved { from, to } => classify_moved_path(root, &from, &to),
    }
}

fn classify_existing_path(root: &Path, path: &Path) -> Option<WorkspaceChange> {
    let relative = watch_relative_path(root, path)?;
    if should_ignore_path(&relative) {
        return None;
    }
    special_workspace_change(&relative)
        .or_else(|| manifest_or_lockfile_change(&relative))
        .or_else(|| Some(WorkspaceChange::FileChanged(relative)))
}

fn classify_deleted_path(root: &Path, path: &Path) -> Option<WorkspaceChange> {
    let relative = watch_relative_path(root, path)?;
    if should_ignore_path(&relative) {
        return None;
    }
    special_workspace_change(&relative)
        .or_else(|| manifest_or_lockfile_change(&relative))
        .or_else(|| Some(WorkspaceChange::FileDeleted(relative)))
}

fn classify_moved_path(root: &Path, from: &Path, to: &Path) -> Vec<WorkspaceChange> {
    match (watch_relative_path(root, from), watch_relative_path(root, to)) {
        (Some(from), Some(to)) if should_ignore_path(&from) && should_ignore_path(&to) => Vec::new(),
        (Some(from), Some(to)) if should_ignore_path(&from) => {
            classify_existing_path(root, &root.join(to)).into_iter().collect()
        }
        (Some(from), Some(to)) if should_ignore_path(&to) => {
            classify_deleted_path(root, &root.join(from)).into_iter().collect()
        }
        (Some(from), Some(to)) => classify_visible_move(from, to),
        (None, Some(to)) => classify_existing_path(root, &root.join(to)).into_iter().collect(),
        (Some(from), None) => classify_deleted_path(root, &root.join(from)).into_iter().collect(),
        (None, None) => Vec::new(),
    }
}

fn classify_visible_move(from: PathBuf, to: PathBuf) -> Vec<WorkspaceChange> {
    let mut changes = [
        special_workspace_change(&from),
        special_workspace_change(&to),
        manifest_or_lockfile_change(&from),
        manifest_or_lockfile_change(&to),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if !changes.is_empty() {
        changes.sort();
        changes.dedup();
        return changes;
    }
    vec![WorkspaceChange::FileMoved { from, to }]
}

fn special_workspace_change(path: &Path) -> Option<WorkspaceChange> {
    if is_git_head_path(path) {
        return Some(WorkspaceChange::GitHeadChanged);
    }
    if path == Path::new(".git/index") {
        return Some(WorkspaceChange::GitIndexChanged);
    }
    if is_prompt_or_house_rule(path) {
        return Some(WorkspaceChange::PromptOrHouseRuleChanged);
    }
    is_ruleset_path(path).then_some(WorkspaceChange::RuleSetChanged)
}

fn manifest_or_lockfile_change(path: &Path) -> Option<WorkspaceChange> {
    let name = path.file_name()?.to_str()?;
    if is_lockfile_name(name) {
        return Some(WorkspaceChange::LockfileChanged(path.to_path_buf()));
    }
    is_manifest_name(name).then(|| WorkspaceChange::ManifestChanged(path.to_path_buf()))
}

fn is_git_head_path(path: &Path) -> bool {
    path == Path::new(".git/HEAD") || path.starts_with(".git/refs")
}

fn is_prompt_or_house_rule(path: &Path) -> bool {
    path.starts_with(".kuzushi/prompts") || path.starts_with(".kuzushi/house-rules")
}

fn is_ruleset_path(path: &Path) -> bool {
    path.starts_with(".kuzushi/rules")
        || path.starts_with(".kuzushi/rule-sets")
        || matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some(".semgrep.yml" | ".semgrep.yaml" | "semgrep.yml" | "semgrep.yaml")
        )
}

fn is_manifest_name(name: &str) -> bool {
    matches!(
        name,
        "package.json" | "Cargo.toml" | "go.mod" | "pyproject.toml" | "pom.xml"
    )
}

fn is_lockfile_name(name: &str) -> bool {
    matches!(
        name,
        "package-lock.json" | "pnpm-lock.yaml" | "yarn.lock" | "Cargo.lock" | "go.sum"
    )
}

fn watch_relative_path(root: &Path, path: &Path) -> Option<PathBuf> {
    let relative = path.strip_prefix(root).unwrap_or(path);
    clean_relative_path(relative)
}

fn clean_relative_path(path: &Path) -> Option<PathBuf> {
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => return None,
        }
    }
    (!clean.as_os_str().is_empty()).then_some(clean)
}
