//! Full source capture with bounded durable projection batches.
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceIndexProgress {
    ReadFiles(usize),
    PersistedUpdates { completed: usize, total: usize },
}

pub(crate) fn index_workspace_snapshot_cancellable(
    workspace: &WorkspaceTarget,
    progress: &mut dyn FnMut(SourceIndexProgress),
    canceled: &dyn Fn() -> bool,
) -> Result<IndexedWorkspaceSnapshot> {
    source_walk::check_cancellation(canceled)?;
    workspace.ensure_state_dir()?;
    let store = ContentStore::open(workspace.objects_dir())?;
    let files = collect_files(workspace.root(), &store, progress, canceled)?;
    source_walk::check_cancellation(canceled)?;
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
        created_at: "snapshot-content-addressed".into(),
    })?;
    commit_projection(
        workspace, &snapshot, &tree, &metadata, &files, progress, canceled,
    )
}

pub(super) fn collect_files(
    root: &Path,
    store: &ContentStore,
    progress: &mut dyn FnMut(SourceIndexProgress),
    canceled: &dyn Fn() -> bool,
) -> Result<Vec<IndexedFile>> {
    let root = root.canonicalize()?;
    let mut files = Vec::new();
    let mut budget = IndexBudget::default();
    source_walk::walk_source_files(&root, canceled, &mut |event| {
        if let source_walk::SourceWalkEvent::File(path) = event {
            let (metadata, bytes) = read_budgeted_source_file(&path, &mut budget, canceled)?;
            files.push(store_indexed_file(&root, &path, store, &metadata, &bytes)?);
        }
        progress(SourceIndexProgress::ReadFiles(files.len()));
        Ok(())
    })?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

pub(super) fn commit_projection(
    workspace: &WorkspaceTarget,
    snapshot: &ObjectRef,
    tree: &ObjectRef,
    metadata: &SnapshotMetadata,
    files: &[IndexedFile],
    progress: &mut dyn FnMut(SourceIndexProgress),
    canceled: &dyn Fn() -> bool,
) -> Result<IndexedWorkspaceSnapshot> {
    let commands = index_projection_commands(snapshot, tree, metadata, files);
    let total = commands.len();
    let receipts = StorageWriterActor::commit_source_index(
        workspace.event_log_dir(),
        workspace.findings_db_path(),
        commands,
        &mut |completed| progress(SourceIndexProgress::PersistedUpdates { completed, total }),
        canceled,
    )?;
    Ok(IndexedWorkspaceSnapshot {
        snapshot_hash: snapshot.hash.as_str().into(),
        tree_hash: tree.hash.as_str().into(),
        file_count: files.len(),
        applied_seq: receipts.last().map_or(0, |receipt| receipt.committed_seq),
        files: files.iter().map(indexed_snapshot_file).collect(),
    })
}

#[cfg(test)]
mod tests;
