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
        let mut watcher = RecommendedWatcher::new(
            move |event| {
                let (changes, state_artifact_paths) =
                    classify_notify_result_with_state(&classifier_root, event);
                if !changes.is_empty() || !state_artifact_paths.is_empty() {
                    sink(changes, state_artifact_paths);
                }
            },
            watcher_config(),
        )
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

/// Recursive watch config: never follow symlinks — bazel convenience
/// symlinks (bazel-bin/…) point at an execroot with tens of thousands of
/// directories that churn during builds.
fn watcher_config() -> notify::Config {
    notify::Config::default().with_follow_symlinks(false)
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
    if is_sqlite_side_file(&relative) || is_high_churn_state_internal(&relative) {
        return None;
    }
    if relative.starts_with(".kuzushi/v3") {
        return Some(relative);
    }
    if relative == Path::new(".kuzushi/codeql-db") {
        return Some(PathBuf::from(".kuzushi/codeql-db"));
    }
    is_legacy_workspace_artifact(&relative).then_some(relative)
}

/// Per-write internals that flood notify while a headless scan writes into
/// the same workspace — the watcher storm that pinned a core: run-dir
/// contents (live `trace.jsonl` appends, child logs) except the terminal
/// `done.json` sentinel, event-log segment appends (one fsync'd write per
/// observation), and content-store blobs. External store progress still
/// surfaces through the projection sqlite main file on WAL checkpoint and
/// through `done.json`/`queue.json` transitions.
fn is_high_churn_state_internal(path: &Path) -> bool {
    if path.starts_with(".kuzushi/v3/runs") {
        return path.file_name() != Some(std::ffi::OsStr::new("done.json"));
    }
    path.starts_with(".kuzushi/v3/log") || path.starts_with(".kuzushi/v3/objects")
}

fn is_sqlite_side_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.ends_with(".sqlite3-shm")
                || name.ends_with(".sqlite3-wal")
                || name.ends_with(".sqlite3-journal")
        })
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
    fn watcher_ignores_all_sqlite_side_files_but_keeps_the_main_database() {
        let root = Path::new("/tmp/workspace");

        for side in ["-shm", "-wal", "-journal"] {
            assert_eq!(
                runtime_state_path(root, &root.join(format!(".kuzushi/v3/index.sqlite3{side}"))),
                None,
                "{side} must not wake the shell per store write"
            );
        }
        assert_eq!(
            runtime_state_path(root, &root.join(".kuzushi/v3/index.sqlite3")),
            Some(PathBuf::from(".kuzushi/v3/index.sqlite3"))
        );
    }

    /// A headless scan writing into the watched workspace must not generate
    /// per-write watcher work: a burst of run-dir appends, event-log segment
    /// appends, WAL touches, and blob writes classifies to zero changes and
    /// zero state events — only the terminal sentinel and queue transitions
    /// surface.
    #[test]
    fn store_write_burst_produces_no_watcher_work() {
        let root = Path::new("/tmp/workspace");
        let churn = [
            ".kuzushi/v3/runs/run-1/trace.jsonl",
            ".kuzushi/v3/runs/run-1/summary.json",
            ".kuzushi/v3/log/events-000000.jsonl",
            ".kuzushi/v3/objects/ab/abcdef",
            ".kuzushi/v3/index.sqlite3-wal",
        ];
        for _ in 0..200 {
            for path in churn {
                let event = Event {
                    kind: EventKind::Modify(ModifyKind::Any),
                    paths: vec![root.join(path)],
                    attrs: Default::default(),
                };
                let (changes, state) = classify_notify_event_with_state(root, event);
                assert!(changes.is_empty(), "{path} classified as a source change");
                assert!(state.is_empty(), "{path} classified as a state event");
            }
        }

        let sentinel = Event {
            kind: EventKind::Create(notify::event::CreateKind::File),
            paths: vec![root.join(".kuzushi/v3/runs/run-1/done.json")],
            attrs: Default::default(),
        };
        let (_, state) = classify_notify_event_with_state(root, sentinel);
        assert_eq!(state, vec![PathBuf::from(".kuzushi/v3/runs/run-1/done.json")]);

        let queue = Event {
            kind: EventKind::Modify(ModifyKind::Any),
            paths: vec![root.join(".kuzushi/v3/campaigns/camp/queue.json")],
            attrs: Default::default(),
        };
        let (_, state) = classify_notify_event_with_state(root, queue);
        assert_eq!(
            state,
            vec![PathBuf::from(".kuzushi/v3/campaigns/camp/queue.json")]
        );
    }

    /// The recursive watch must never cross symlink boundaries: bazel's
    /// convenience symlinks point at an execroot with tens of thousands of
    /// churning directories.
    #[test]
    fn watcher_config_never_follows_symlinks() {
        assert!(!watcher_config().follow_symlinks());
    }

    /// A bazel build churning under the repo's bazel-* convenience symlinks
    /// must classify to zero changes and zero state events — otherwise every
    /// build floods the shell with broad cache invalidations.
    #[test]
    fn bazel_build_burst_produces_no_watcher_work() {
        let root = Path::new("/tmp/workspace");
        let churn = [
            "bazel-bin/src/cpp/libfoo.so",
            "bazel-out/k8-opt/bin/tool",
            "bazel-testlogs/suite/test.log",
            "bazel-workspace/external/dep/BUILD",
        ];
        for _ in 0..200 {
            for path in churn {
                let event = Event {
                    kind: EventKind::Modify(ModifyKind::Any),
                    paths: vec![root.join(path)],
                    attrs: Default::default(),
                };
                let (changes, state) = classify_notify_event_with_state(root, event);
                assert!(changes.is_empty(), "{path} classified as a source change");
                assert!(state.is_empty(), "{path} classified as a state event");
            }
        }
    }
}
