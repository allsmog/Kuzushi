use crate::content_store::{ContentStore, ObjectRef, TargetSnapshot, TreeEntry, TreeEntryKind};
use crate::identity::hash_parts;
use crate::storage_v3::writer_actor::{
    FileFactWrite, SnapshotWrite, StorageWriterActor, WatcherCommand, WriterCommand,
};
use crate::workspace::{target_git_metadata, WorkspaceTarget};
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

mod change_coalescing;
mod language;

pub use change_coalescing::coalesce_changes;

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

pub fn plan_for_change(change: &WorkspaceChange) -> ReindexPlan {
    match change {
        WorkspaceChange::FileChanged(path) if is_route_or_controller(path) => {
            ReindexPlan::FileFactsAndLocalAttackSurface
        }
        WorkspaceChange::FileChanged(_) | WorkspaceChange::FileMoved { .. } => {
            ReindexPlan::FileFacts
        }
        WorkspaceChange::FileDeleted(_) => ReindexPlan::FullInventory,
        WorkspaceChange::ManifestChanged(_) | WorkspaceChange::LockfileChanged(_) => {
            ReindexPlan::DependencyIndex
        }
        WorkspaceChange::GitHeadChanged => ReindexPlan::FullSnapshot,
        WorkspaceChange::GitIndexChanged => ReindexPlan::FullInventory,
        WorkspaceChange::RuleSetChanged => ReindexPlan::FullDeterministicScan,
        WorkspaceChange::PromptOrHouseRuleChanged => ReindexPlan::MarkStaleOnly,
    }
}

pub fn should_ignore_path(path: &Path) -> bool {
    let text = path.to_string_lossy();
    text.contains(".kuzushi/v3/")
        || text.contains(".git/objects/")
        || path
            .components()
            .filter_map(|component| component.as_os_str().to_str())
            .any(|part| matches!(part, "node_modules" | "target" | "dist"))
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
    collect_indexed_files_from(root, root, store, &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn collect_indexed_files_from(
    root: &Path,
    dir: &Path,
    store: &ContentStore,
    files: &mut Vec<IndexedFile>,
) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("Could not read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if should_ignore_path(&path) {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_dir() {
            collect_indexed_files_from(root, &path, store, files)?;
        } else if kind.is_file() {
            files.push(index_file(root, &path, store)?);
        }
    }
    Ok(())
}

fn index_file(root: &Path, path: &Path, store: &ContentStore) -> Result<IndexedFile> {
    let bytes = fs::read(path).with_context(|| format!("Could not read {}", path.display()))?;
    let metadata = fs::metadata(path).with_context(|| format!("Could not stat {}", path.display()))?;
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
