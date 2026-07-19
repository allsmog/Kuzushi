use super::{coalesce_changes, should_ignore_path, WorkspaceChange};
use anyhow::{Context, Result};
use notify::{
    event::{ModifyKind, RenameMode},
    Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
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

pub struct LiveWorkspaceWatcher {
    _watcher: RecommendedWatcher,
    scope: WatchScope,
}

impl LiveWorkspaceWatcher {
    pub fn start(
        root: impl AsRef<Path>,
        mut sink: impl FnMut(Vec<WorkspaceChange>) + Send + 'static,
    ) -> Result<Self> {
        Self::start_with_state_events(root, move |changes, _state_artifact_paths| {
            if !changes.is_empty() {
                sink(changes);
            }
        })
    }

    pub fn start_with_state_events(
        root: impl AsRef<Path>,
        mut sink: impl FnMut(Vec<WorkspaceChange>, Vec<PathBuf>) + Send + 'static,
    ) -> Result<Self> {
        let scope = workspace_watch_scope(root);
        let classifier_root = scope.root.clone();
        let mut watcher = notify::recommended_watcher(move |event| {
            let (changes, state_artifact_paths) =
                classify_notify_result_with_state(&classifier_root, event);
            if !changes.is_empty() || !state_artifact_paths.is_empty() {
                sink(changes, state_artifact_paths);
            }
        })
        .context("could not start workspace watcher")?;
        watch_scope_roots(&mut watcher, &scope)?;
        Ok(Self {
            _watcher: watcher,
            scope,
        })
    }

    pub fn scope(&self) -> &WatchScope {
        &self.scope
    }
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

pub fn classify_notify_event(root: &Path, event: Event) -> Vec<WorkspaceChange> {
    classify_watcher_events(root, notify_event_to_watch_events(event))
}

pub fn classify_notify_event_with_state(
    root: &Path,
    event: Event,
) -> (Vec<WorkspaceChange>, Vec<PathBuf>) {
    let mut state_artifact_paths = event
        .paths
        .iter()
        .filter_map(|path| runtime_state_path(root, path))
        .collect::<Vec<_>>();
    state_artifact_paths.sort();
    state_artifact_paths.dedup();
    (classify_notify_event(root, event), state_artifact_paths)
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
    if let Some(change) = special_workspace_change(&relative) {
        return Some(change);
    }
    if should_ignore_path(&relative) {
        return None;
    }
    manifest_or_lockfile_change(&relative)
        .or(Some(WorkspaceChange::FileChanged(relative)))
}

fn classify_deleted_path(root: &Path, path: &Path) -> Option<WorkspaceChange> {
    let relative = watch_relative_path(root, path)?;
    if let Some(change) = special_workspace_change(&relative) {
        return Some(change);
    }
    if should_ignore_path(&relative) {
        return None;
    }
    manifest_or_lockfile_change(&relative)
        .or(Some(WorkspaceChange::FileDeleted(relative)))
}

fn classify_moved_path(root: &Path, from: &Path, to: &Path) -> Vec<WorkspaceChange> {
    let relative = (watch_relative_path(root, from), watch_relative_path(root, to));
    let mut changes = moved_special_changes(&relative);
    changes.extend(classify_moved_source_changes(root, relative));
    coalesce_changes(changes)
}

fn classify_moved_source_changes(
    root: &Path,
    relative: (Option<PathBuf>, Option<PathBuf>),
) -> Vec<WorkspaceChange> {
    match relative {
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

fn moved_special_changes(paths: &(Option<PathBuf>, Option<PathBuf>)) -> Vec<WorkspaceChange> {
    let mut changes = [&paths.0, &paths.1]
        .into_iter()
        .filter_map(|path| path.as_deref())
        .filter_map(special_workspace_change)
        .collect::<Vec<_>>();
    changes.sort();
    changes.dedup();
    changes
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

fn classify_notify_result_with_state(
    root: &Path,
    event: notify::Result<Event>,
) -> (Vec<WorkspaceChange>, Vec<PathBuf>) {
    match event {
        Ok(event) => classify_notify_event_with_state(root, event),
        Err(_) => (
            vec![WorkspaceChange::GitHeadChanged],
            vec![PathBuf::from(".kuzushi/v3")],
        ),
    }
}

fn runtime_state_path(root: &Path, path: &Path) -> Option<PathBuf> {
    let relative = watch_relative_path(root, path)?;
    if is_sqlite_shared_memory(&relative) {
        return None;
    }
    let codeql_database = crate::workspace::workspace_codeql_db_path("");
    if relative.starts_with(&codeql_database) {
        return Some(codeql_database);
    }
    if relative.starts_with(".kuzushi/v3") {
        return Some(relative);
    }
    is_legacy_workspace_artifact(&relative).then_some(relative)
}

fn is_sqlite_shared_memory(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".sqlite3-shm"))
}

fn is_legacy_workspace_artifact(path: &Path) -> bool {
    matches!(
        path.to_str(),
        Some(
            ".kuzushi/context-snapshot.json"
                | ".kuzushi/entry-points.json"
                | ".kuzushi/threat-model.json"
                | ".kuzushi/threat-model-pasta.json"
                | ".kuzushi/cpg.bin"
                | ".kuzushi/threat-intel/candidates.json"
        )
    )
}

fn watch_scope_roots(watcher: &mut RecommendedWatcher, scope: &WatchScope) -> Result<()> {
    for root in &scope.roots {
        if root.exists() {
            watcher
                .watch(root, RecursiveMode::Recursive)
                .with_context(|| format!("could not watch {}", root.display()))?;
        }
    }
    Ok(())
}

fn notify_event_to_watch_events(event: Event) -> Vec<WatchEvent> {
    match event.kind {
        EventKind::Create(_) => paths_to_events(event.paths, WatchEvent::Created),
        EventKind::Remove(_) => paths_to_events(event.paths, WatchEvent::Deleted),
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) if event.paths.len() >= 2 => {
            vec![WatchEvent::Moved {
                from: event.paths[0].clone(),
                to: event.paths[1].clone(),
            }]
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::From)) => {
            paths_to_events(event.paths, WatchEvent::Deleted)
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => {
            paths_to_events(event.paths, WatchEvent::Created)
        }
        EventKind::Modify(_) | EventKind::Any | EventKind::Other => {
            paths_to_events(event.paths, WatchEvent::Modified)
        }
        EventKind::Access(_) => Vec::new(),
    }
}

fn paths_to_events(
    paths: Vec<PathBuf>,
    event: impl Fn(PathBuf) -> WatchEvent,
) -> Vec<WatchEvent> {
    paths.into_iter().map(event).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watcher_ignores_sqlite_shared_memory_but_keeps_wal_changes() {
        let root = Path::new("/tmp/workspace");

        assert_eq!(
            runtime_state_path(root, &root.join(".kuzushi/v3/index.sqlite3-shm")),
            None
        );
        assert_eq!(
            runtime_state_path(root, &root.join(".kuzushi/v3/index.sqlite3-wal")),
            Some(PathBuf::from(".kuzushi/v3/index.sqlite3-wal"))
        );
    }
}
