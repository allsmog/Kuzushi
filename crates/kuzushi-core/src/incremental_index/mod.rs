use crate::content_store::{
    ContentStore, ObjectKind, ObjectRef, TargetSnapshot, TreeEntry, TreeEntryKind,
};
use crate::identity::{hash_parts, Blake3Hash};
use crate::storage_v3::writer_actor::{
    AuditWrite, FileDeletedWrite, FileFactWrite, SnapshotWrite, StorageWriterActor,
    WatcherCommand, WriterCommand,
};
use crate::workspace::{target_git_metadata, WorkspaceTarget};
use anyhow::{Context, Result};
use serde_json::json;
use rusqlite::{params, OptionalExtension};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

mod change_coalescing;
mod language;
mod watcher;

pub use change_coalescing::coalesce_changes;
pub use watcher::{
    classify_notify_event, classify_notify_event_with_state, classify_watcher_event,
    classify_watcher_events, workspace_watch_scope, LiveWorkspaceWatcher, WatchEvent, WatchScope,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkspaceChange {
    FileChanged(PathBuf),
    FileDeleted(PathBuf),
    FileMoved { from: PathBuf, to: PathBuf },
    ManifestChanged(PathBuf),
    LockfileChanged(PathBuf),
    GitHeadChanged,
    GitIndexChanged,
    RuleSetChanged,
    PromptOrHouseRuleChanged,
}

pub const MAX_INDEXED_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_INDEXED_SNAPSHOT_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_INDEXED_SNAPSHOT_FILES: usize = 200_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReindexPlan {
    MarkStaleOnly,
    FileFacts,
    FileFactsAndLocalAttackSurface,
    DependencyIndex,
    FullInventory,
    FullSnapshot,
    FullDeterministicScan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedWorkspaceSnapshot {
    pub snapshot_hash: String,
    pub tree_hash: String,
    pub file_count: usize,
    pub applied_seq: u64,
    pub files: Vec<IndexedSnapshotFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceIndexUpdate {
    Noop { change_count: usize },
    Invalidated {
        change_count: usize,
        applied_seq: u64,
        summary: String,
    },
    Incremental(IndexedWorkspaceSnapshot),
    Full(IndexedWorkspaceSnapshot),
}

impl WorkspaceIndexUpdate {
    pub fn applied_seq(&self) -> Option<u64> {
        match self {
            Self::Noop { .. } => None,
            Self::Invalidated { applied_seq, .. } => Some(*applied_seq),
            Self::Incremental(snapshot) | Self::Full(snapshot) => Some(snapshot.applied_seq),
        }
    }

    pub fn file_count(&self) -> Option<usize> {
        match self {
            Self::Noop { .. } | Self::Invalidated { .. } => None,
            Self::Incremental(snapshot) | Self::Full(snapshot) => Some(snapshot.file_count),
        }
    }

    pub fn snapshot_hash(&self) -> Option<&str> {
        match self {
            Self::Noop { .. } | Self::Invalidated { .. } => None,
            Self::Incremental(snapshot) | Self::Full(snapshot) => Some(&snapshot.snapshot_hash),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedSnapshotFile {
    pub path: String,
    pub blob_hash: String,
    pub storage_path: PathBuf,
    pub file_size: u64,
    pub language: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedFile {
    path: String,
    blob: ObjectRef,
    storage_path: PathBuf,
    file_size: u64,
    mtime_ns: Option<i64>,
    language: Option<String>,
}

struct SnapshotMetadata {
    workspace_root_fingerprint: String,
    git_commit: Option<String>,
    git_branch: Option<String>,
    dirty_hash: Option<crate::identity::Blake3Hash>,
}

pub fn index_workspace_snapshot(workspace: &WorkspaceTarget) -> Result<IndexedWorkspaceSnapshot> {
    workspace.ensure_state_dir()?;
    let store = ContentStore::open(workspace.objects_dir())?;
    let files = collect_indexed_files(workspace.root(), &store)?;
    let tree = store.put_tree(tree_entries(&files))?;
    let metadata = snapshot_metadata(workspace.root(), &files);
    let snapshot = store.put_snapshot(&TargetSnapshot {
        tree_hash: tree.hash.clone(),
        workspace_root_fingerprint: metadata.workspace_root_fingerprint.clone(),
        git_commit: metadata.git_commit.clone(),
        git_branch: metadata.git_branch.clone(),
        dirty_hash: metadata.dirty_hash.clone(),
        index_hash: None,
        config_hash: None,
        rule_set_hashes: Vec::new(),
        created_at: "snapshot-content-addressed".to_string(),
    })?;
    commit_index_projection(workspace, &snapshot, &tree, &metadata, &files)
}

pub fn index_workspace_changes(
    workspace: &WorkspaceTarget,
    changes: &[WorkspaceChange],
) -> Result<WorkspaceIndexUpdate> {
    let changes = coalesce_changes(changes.iter().cloned());
    match index_mode_for_changes(&changes) {
        ChangeIndexMode::Noop => Ok(WorkspaceIndexUpdate::Noop {
            change_count: changes.len(),
        }),
        ChangeIndexMode::Invalidate => record_workspace_invalidation(workspace, &changes),
        ChangeIndexMode::FullSnapshot => {
            index_workspace_snapshot(workspace).map(WorkspaceIndexUpdate::Full)
        }
        ChangeIndexMode::FileFacts => index_file_fact_changes_or_full_snapshot(workspace, &changes),
    }
}

enum ChangeIndexMode {
    Noop,
    FileFacts,
    Invalidate,
    FullSnapshot,
}

fn index_mode_for_changes(changes: &[WorkspaceChange]) -> ChangeIndexMode {
    if changes.is_empty() {
        return ChangeIndexMode::Noop;
    }
    if changes_require_full_snapshot(changes) {
        return ChangeIndexMode::FullSnapshot;
    }
    if changes_require_invalidation(changes) {
        return ChangeIndexMode::Invalidate;
    }
    ChangeIndexMode::FileFacts
}

fn index_file_fact_changes_or_full_snapshot(
    workspace: &WorkspaceTarget,
    changes: &[WorkspaceChange],
) -> Result<WorkspaceIndexUpdate> {
    match index_workspace_file_fact_changes(workspace, changes) {
        Ok(snapshot) => Ok(WorkspaceIndexUpdate::Incremental(snapshot)),
        Err(_) => index_workspace_snapshot(workspace).map(WorkspaceIndexUpdate::Full),
    }
}

pub fn plan_for_change(change: &WorkspaceChange) -> ReindexPlan {
    match change {
        WorkspaceChange::FileChanged(path) if is_route_or_controller(path) => {
            ReindexPlan::FileFactsAndLocalAttackSurface
        }
        WorkspaceChange::FileChanged(_)
        | WorkspaceChange::FileDeleted(_)
        | WorkspaceChange::FileMoved { .. } => {
            ReindexPlan::FileFacts
        }
        WorkspaceChange::ManifestChanged(_) | WorkspaceChange::LockfileChanged(_) => {
            ReindexPlan::DependencyIndex
        }
        WorkspaceChange::GitHeadChanged => ReindexPlan::FullSnapshot,
        WorkspaceChange::GitIndexChanged => ReindexPlan::FullInventory,
        WorkspaceChange::RuleSetChanged => ReindexPlan::FullDeterministicScan,
        WorkspaceChange::PromptOrHouseRuleChanged => ReindexPlan::MarkStaleOnly,
    }
}

fn changes_require_full_snapshot(changes: &[WorkspaceChange]) -> bool {
    changes.iter().any(|change| {
        matches!(
            change,
            WorkspaceChange::GitHeadChanged | WorkspaceChange::GitIndexChanged
        )
    })
}

fn changes_require_invalidation(changes: &[WorkspaceChange]) -> bool {
    changes.iter().any(|change| {
        matches!(
            plan_for_change(change),
            ReindexPlan::DependencyIndex
                | ReindexPlan::FullInventory
                | ReindexPlan::FullDeterministicScan
                | ReindexPlan::MarkStaleOnly
        )
    })
}

fn record_workspace_invalidation(
    workspace: &WorkspaceTarget,
    changes: &[WorkspaceChange],
) -> Result<WorkspaceIndexUpdate> {
    workspace.ensure_state_dir()?;
    let summary = workspace_invalidation_summary(changes);
    let receipts = StorageWriterActor::commit_blocking_many(
        workspace.event_log_dir(),
        workspace.findings_db_path(),
        vec![WriterCommand::Decision(
            crate::storage_v3::writer_actor::DecisionCommand::RecordAudit(AuditWrite {
                event_kind: crate::event_log::EventKind::DiagnosticRecorded,
                actor: "incremental-index".to_string(),
                run_id: None,
                stable_fp: None,
                subject: Some("workspace-invalidation".to_string()),
                summary: summary.clone(),
                details: json!({
                    "code": "workspace.invalidation",
                    "changes": changes.iter().map(workspace_change_label).collect::<Vec<_>>(),
                    "plans": changes.iter().map(|change| format!("{:?}", plan_for_change(change))).collect::<Vec<_>>(),
                }),
            }),
        )],
    )?;
    Ok(WorkspaceIndexUpdate::Invalidated {
        change_count: changes.len(),
        applied_seq: receipts.last().map_or(0, |receipt| receipt.committed_seq),
        summary,
    })
}

fn workspace_invalidation_summary(changes: &[WorkspaceChange]) -> String {
    if changes.iter().any(|change| matches!(change, WorkspaceChange::RuleSetChanged)) {
        return "rule-set changed; deterministic scanner observations marked stale".to_string();
    }
    if changes.iter().any(|change| {
        matches!(
            change,
            WorkspaceChange::ManifestChanged(_) | WorkspaceChange::LockfileChanged(_)
        )
    }) {
        return "dependency inputs changed; dependency index marked stale".to_string();
    }
    if changes
        .iter()
        .any(|change| matches!(change, WorkspaceChange::PromptOrHouseRuleChanged))
    {
        return "prompt or house-rule changed; model-derived results marked stale".to_string();
    }
    "workspace inputs changed; derived indexes marked stale".to_string()
}

fn workspace_change_label(change: &WorkspaceChange) -> String {
    match change {
        WorkspaceChange::FileChanged(path) => format!("file-changed:{}", path.display()),
        WorkspaceChange::FileDeleted(path) => format!("file-deleted:{}", path.display()),
        WorkspaceChange::FileMoved { from, to } => {
            format!("file-moved:{}->{}", from.display(), to.display())
        }
        WorkspaceChange::ManifestChanged(path) => format!("manifest-changed:{}", path.display()),
        WorkspaceChange::LockfileChanged(path) => format!("lockfile-changed:{}", path.display()),
        WorkspaceChange::GitHeadChanged => "git-head-changed".to_string(),
        WorkspaceChange::GitIndexChanged => "git-index-changed".to_string(),
        WorkspaceChange::RuleSetChanged => "rule-set-changed".to_string(),
        WorkspaceChange::PromptOrHouseRuleChanged => "prompt-or-house-rule-changed".to_string(),
    }
}

fn index_workspace_file_fact_changes(
    workspace: &WorkspaceTarget,
    changes: &[WorkspaceChange],
) -> Result<IndexedWorkspaceSnapshot> {
    workspace.ensure_state_dir()?;
    let store = ContentStore::open(workspace.objects_dir())?;
    let mut files = latest_projected_snapshot(workspace)?;
    for change in changes {
        apply_file_fact_change(workspace.root(), &store, &mut files, change)?;
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let tree = store.put_tree(tree_entries(&files))?;
    let metadata = snapshot_metadata(workspace.root(), &files);
    let snapshot = store.put_snapshot(&TargetSnapshot {
        tree_hash: tree.hash.clone(),
        workspace_root_fingerprint: metadata.workspace_root_fingerprint.clone(),
        git_commit: metadata.git_commit.clone(),
        git_branch: metadata.git_branch.clone(),
        dirty_hash: metadata.dirty_hash.clone(),
        index_hash: None,
        config_hash: None,
        rule_set_hashes: Vec::new(),
        created_at: "snapshot-content-addressed".to_string(),
    })?;
    commit_incremental_projection(workspace, &snapshot, &tree, &metadata, &files, changes)
}

pub fn should_ignore_path(path: &Path) -> bool {
    path.components()
        .filter_map(|component| component.as_os_str().to_str())
        .any(|part| {
            matches!(
                part,
                ".git" | ".kuzushi" | "node_modules" | "target" | "dist"
            )
        })
}

fn is_route_or_controller(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|part| matches!(part, "routes" | "controllers" | "handlers"))
    })
}

fn collect_indexed_files(root: &Path, store: &ContentStore) -> Result<Vec<IndexedFile>> {
    let mut files = Vec::new();
    let mut budget = IndexBudget::default();
    collect_indexed_files_from(root, root, store, &mut files, &mut budget)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn collect_indexed_files_from(
    root: &Path,
    dir: &Path,
    store: &ContentStore,
    files: &mut Vec<IndexedFile>,
    budget: &mut IndexBudget,
) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("Could not read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if should_ignore_path(&path) {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_dir() {
            collect_indexed_files_from(root, &path, store, files, budget)?;
        } else if kind.is_file() {
            let indexed = index_file(root, &path, store)?;
            budget.record(indexed.file_size)?;
            files.push(indexed);
        }
    }
    Ok(())
}

fn latest_projected_snapshot(workspace: &WorkspaceTarget) -> Result<Vec<IndexedFile>> {
    let conn = crate::sqlite_connection::open_file(&workspace.findings_db_path())?;
    let snapshot_hash = conn
        .query_row(
            "select snapshot_hash from target_snapshots order by created_at desc, rowid desc limit 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .context("workspace has no indexed snapshot yet")?;
    let mut statement = conn.prepare(
        r#"
        select indexed_files.path, indexed_files.blob_hash, indexed_files.file_size,
               indexed_files.mtime_ns, indexed_files.language, blobs.storage_path
        from indexed_files
        left join blobs on blobs.blob_hash = indexed_files.blob_hash
        where snapshot_hash = ?1
        order by indexed_files.path
        "#,
    )?;
    let rows = statement.query_map(params![snapshot_hash], projected_indexed_file)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn projected_indexed_file(row: &rusqlite::Row<'_>) -> rusqlite::Result<IndexedFile> {
    let blob_hash: String = row.get(1)?;
    let file_size_i64: i64 = row.get(2)?;
    let file_size = u64::try_from(file_size_i64).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    let hash = Blake3Hash::new(blob_hash)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
    Ok(IndexedFile {
        path: row.get(0)?,
        blob: ObjectRef {
            kind: ObjectKind::Blob,
            hash,
            size_bytes: file_size,
        },
        storage_path: row
            .get::<_, Option<String>>(5)?
            .map(PathBuf::from)
            .unwrap_or_default(),
        file_size,
        mtime_ns: row.get(3)?,
        language: row.get(4)?,
    })
}

fn apply_file_fact_change(
    root: &Path,
    store: &ContentStore,
    files: &mut Vec<IndexedFile>,
    change: &WorkspaceChange,
) -> Result<()> {
    match change {
        WorkspaceChange::FileChanged(path) => replace_indexed_file(root, store, files, path),
        WorkspaceChange::FileMoved { from, to } => {
            remove_indexed_file(files, from);
            replace_indexed_file(root, store, files, to)
        }
        WorkspaceChange::FileDeleted(path) => {
            remove_indexed_file(files, path);
            Ok(())
        }
        _ => Ok(()),
    }
}

fn replace_indexed_file(
    root: &Path,
    store: &ContentStore,
    files: &mut Vec<IndexedFile>,
    relative_path: &Path,
) -> Result<()> {
    let absolute_path = root.join(relative_path);
    let indexed = index_file(root, &absolute_path, store)?;
    remove_indexed_file(files, relative_path);
    IndexBudget::from_files(files).record(indexed.file_size)?;
    files.push(indexed);
    Ok(())
}

fn remove_indexed_file(files: &mut Vec<IndexedFile>, relative_path: &Path) {
    let path = relative_path.to_string_lossy().replace('\\', "/");
    files.retain(|file| file.path != path);
}

fn index_file(root: &Path, path: &Path, store: &ContentStore) -> Result<IndexedFile> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("Could not stat {}", path.display()))?;
    validate_indexed_file(path, &metadata)?;
    let bytes = read_indexed_file(path)?;
    let blob = store.put_blob(&bytes)?;
    let storage_path = store.object_path(&blob.hash);
    Ok(IndexedFile {
        path: workspace_relative_path(root, path)?,
        blob,
        storage_path,
        file_size: metadata.len(),
        mtime_ns: modified_time_ns(&metadata),
        language: language::language_for_path(path),
    })
}

#[derive(Default)]
struct IndexBudget {
    files: usize,
    bytes: u64,
}

impl IndexBudget {
    fn from_files(files: &[IndexedFile]) -> Self {
        Self {
            files: files.len(),
            bytes: files
                .iter()
                .fold(0_u64, |total, file| total.saturating_add(file.file_size)),
        }
    }

    fn record(&mut self, bytes: u64) -> Result<()> {
        self.files = self.files.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
        anyhow::ensure!(
            self.files <= MAX_INDEXED_SNAPSHOT_FILES,
            "workspace index exceeds the {MAX_INDEXED_SNAPSHOT_FILES}-file safety limit"
        );
        anyhow::ensure!(
            self.bytes <= MAX_INDEXED_SNAPSHOT_BYTES,
            "workspace index exceeds the {MAX_INDEXED_SNAPSHOT_BYTES}-byte safety limit"
        );
        Ok(())
    }
}

fn validate_indexed_file(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    anyhow::ensure!(metadata.is_file(), "Indexed path is not a regular file: {}", path.display());
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "Indexed path must not be a symlink: {}",
        path.display()
    );
    anyhow::ensure!(
        metadata.len() <= MAX_INDEXED_FILE_BYTES,
        "Indexed file exceeds the {MAX_INDEXED_FILE_BYTES}-byte safety limit: {}",
        path.display()
    );
    Ok(())
}

fn read_indexed_file(path: &Path) -> Result<Vec<u8>> {
    let file = open_indexed_file(path)
        .with_context(|| format!("Could not read {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_INDEXED_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_INDEXED_FILE_BYTES,
        "Indexed file grew beyond the {MAX_INDEXED_FILE_BYTES}-byte safety limit: {}",
        path.display()
    );
    Ok(bytes)
}

#[cfg(unix)]
fn open_indexed_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_indexed_file(path: &Path) -> std::io::Result<fs::File> {
    fs::File::open(path)
}

fn commit_incremental_projection(
    workspace: &WorkspaceTarget,
    snapshot: &ObjectRef,
    tree: &ObjectRef,
    metadata: &SnapshotMetadata,
    files: &[IndexedFile],
    changes: &[WorkspaceChange],
) -> Result<IndexedWorkspaceSnapshot> {
    let mut commands = Vec::with_capacity(files.len() + changes.len() + 1);
    commands.push(WriterCommand::Watcher(WatcherCommand::SnapshotIndexed(
        snapshot_write(snapshot, tree, metadata),
    )));
    commands.extend(files.iter().map(|file| {
        WriterCommand::Watcher(WatcherCommand::FileIndexed(file_write(snapshot, file)))
    }));
    commands.extend(changes.iter().filter_map(|change| deleted_file_write(snapshot, change)));
    let receipts = StorageWriterActor::commit_blocking_many(
        workspace.event_log_dir(),
        workspace.findings_db_path(),
        commands,
    )?;
    Ok(IndexedWorkspaceSnapshot {
        snapshot_hash: snapshot.hash.as_str().to_string(),
        tree_hash: tree.hash.as_str().to_string(),
        file_count: files.len(),
        applied_seq: receipts.last().map_or(0, |receipt| receipt.committed_seq),
        files: files.iter().map(indexed_snapshot_file).collect(),
    })
}

fn commit_index_projection(
    workspace: &WorkspaceTarget,
    snapshot: &ObjectRef,
    tree: &ObjectRef,
    metadata: &SnapshotMetadata,
    files: &[IndexedFile],
) -> Result<IndexedWorkspaceSnapshot> {
    let mut commands = Vec::with_capacity(files.len() + 1);
    commands.push(WriterCommand::Watcher(WatcherCommand::SnapshotIndexed(
        snapshot_write(snapshot, tree, metadata),
    )));
    commands.extend(files.iter().map(|file| {
        WriterCommand::Watcher(WatcherCommand::FileIndexed(file_write(snapshot, file)))
    }));
    let receipts = StorageWriterActor::commit_blocking_many(
        workspace.event_log_dir(),
        workspace.findings_db_path(),
        commands,
    )?;
    Ok(IndexedWorkspaceSnapshot {
        snapshot_hash: snapshot.hash.as_str().to_string(),
        tree_hash: tree.hash.as_str().to_string(),
        file_count: files.len(),
        applied_seq: receipts.last().map_or(0, |receipt| receipt.committed_seq),
        files: files.iter().map(indexed_snapshot_file).collect(),
    })
}

fn indexed_snapshot_file(file: &IndexedFile) -> IndexedSnapshotFile {
    IndexedSnapshotFile {
        path: file.path.clone(),
        blob_hash: file.blob.hash.as_str().to_string(),
        storage_path: file.storage_path.clone(),
        file_size: file.file_size,
        language: file.language.clone(),
    }
}

fn snapshot_write(snapshot: &ObjectRef, tree: &ObjectRef, metadata: &SnapshotMetadata) -> SnapshotWrite {
    SnapshotWrite {
        snapshot_hash: snapshot.hash.as_str().to_string(),
        tree_hash: tree.hash.as_str().to_string(),
        workspace_root_fingerprint: metadata.workspace_root_fingerprint.clone(),
        git_commit: metadata.git_commit.clone(),
        git_branch: metadata.git_branch.clone(),
        dirty_hash: metadata.dirty_hash.as_ref().map(|hash| hash.as_str().to_string()),
        index_hash: None,
        config_hash: None,
        actor: "incremental-index".to_string(),
    }
}

fn file_write(snapshot: &ObjectRef, file: &IndexedFile) -> FileFactWrite {
    FileFactWrite {
        snapshot_hash: snapshot.hash.as_str().to_string(),
        path: file.path.clone(),
        blob_hash: file.blob.hash.as_str().to_string(),
        storage_path: Some(file.storage_path.display().to_string()),
        file_size: file.file_size,
        mtime_ns: file.mtime_ns,
        git_blob_oid: None,
        language: file.language.clone(),
        ast_hash: None,
        actor: "incremental-index".to_string(),
    }
}

fn deleted_file_write(snapshot: &ObjectRef, change: &WorkspaceChange) -> Option<WriterCommand> {
    let path = match change {
        WorkspaceChange::FileDeleted(path) => path,
        WorkspaceChange::FileMoved { from, .. } => from,
        _ => return None,
    };
    Some(WriterCommand::Watcher(WatcherCommand::FileDeleted(
        FileDeletedWrite {
            snapshot_hash: snapshot.hash.as_str().to_string(),
            path: path.to_string_lossy().replace('\\', "/"),
            actor: "incremental-index".to_string(),
        },
    )))
}

fn tree_entries(files: &[IndexedFile]) -> Vec<TreeEntry> {
    files
        .iter()
        .map(|file| TreeEntry {
            name: file.path.clone(),
            kind: TreeEntryKind::Blob,
            hash: file.blob.hash.clone(),
            executable: false,
        })
        .collect()
}

fn workspace_root_fingerprint(root: &Path) -> String {
    hash_parts("workspace-root", &[root.to_string_lossy().as_bytes()])
        .as_str()
        .to_string()
}

fn snapshot_metadata(root: &Path, files: &[IndexedFile]) -> SnapshotMetadata {
    let git = target_git_metadata(root);
    SnapshotMetadata {
        workspace_root_fingerprint: workspace_root_fingerprint(root),
        git_commit: git.as_ref().map(|metadata| metadata.sha.clone()),
        git_branch: git.as_ref().and_then(|metadata| metadata.branch.clone()),
        dirty_hash: git
            .as_ref()
            .and_then(|metadata| metadata.dirty.then(|| dirty_files_hash(files))),
    }
}

fn dirty_files_hash(files: &[IndexedFile]) -> crate::identity::Blake3Hash {
    let payload = files
        .iter()
        .map(|file| format!("{}\0{}\0{}", file.path, file.blob.hash.as_str(), file.file_size))
        .collect::<Vec<_>>()
        .join("\n");
    hash_parts("workspace-dirty-files", &[payload.as_bytes()])
}

fn workspace_relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("{} is outside {}", path.display(), root.display()))?;
    Ok(relative
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect::<Vec<_>>()
        .join("/"))
}

fn modified_time_ns(metadata: &fs::Metadata) -> Option<i64> {
    let duration = metadata.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(duration.as_nanos()).ok()
}

#[cfg(test)]
mod tests;
