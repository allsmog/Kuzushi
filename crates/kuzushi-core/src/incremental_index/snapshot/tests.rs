use super::*;
use std::cell::Cell;

fn fixture() -> (tempfile::TempDir, WorkspaceTarget) {
    let root = tempfile::tempdir().unwrap();
    for number in 0..260 {
        fs::write(
            root.path().join(format!("owned-{number:03}.txt")),
            format!("Owned inert source {number}\n"),
        )
        .unwrap();
    }
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    (root, workspace)
}

#[test]
fn batched_source_snapshot_preserves_all_blobs_files_and_event_sequences() {
    let (root, workspace) = fixture();
    let mut progress = Vec::new();
    let result = index_workspace_snapshot_cancellable(
        &workspace,
        &mut |event| progress.push(event),
        &|| false,
    )
    .unwrap();
    assert_eq!(result.file_count, 260);
    assert_eq!(result.applied_seq, 261);
    assert_eq!(
        result.tree_hash,
        current_workspace_tree_hash(root.path()).unwrap()
    );
    let batches = progress
        .into_iter()
        .filter_map(|event| match event {
            SourceIndexProgress::PersistedUpdates { completed, total } => {
                assert_eq!(total, 261);
                Some(completed)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(batches, [128, 256, 261]);
    let store = ContentStore::open(workspace.objects_dir()).unwrap();
    for file in &result.files {
        assert_eq!(
            store
                .get(&Blake3Hash::new(file.blob_hash.clone()).unwrap())
                .unwrap(),
            fs::read(root.path().join(&file.path)).unwrap()
        );
    }
    let log = crate::event_log::EventLog::open(workspace.event_log_dir()).unwrap();
    log.verify_chain().unwrap();
    assert_eq!(log.read_all().unwrap().len(), 261);
}

#[test]
fn cancellation_after_one_batch_keeps_durable_work_and_explicit_retry_recovers() {
    let (_root, workspace) = fixture();
    let canceled = Cell::new(false);
    let result = index_workspace_snapshot_cancellable(
        &workspace,
        &mut |event| {
            if matches!(
                event,
                SourceIndexProgress::PersistedUpdates { completed: 128, .. }
            ) {
                canceled.set(true);
            }
        },
        &|| canceled.get(),
    );
    assert!(result.unwrap_err().to_string().contains("canceled"));
    let log = crate::event_log::EventLog::open(workspace.event_log_dir()).unwrap();
    assert_eq!(log.read_all().unwrap().len(), 128);
    let recovered =
        index_workspace_snapshot_cancellable(&workspace, &mut |_| {}, &|| false).unwrap();
    assert_eq!(recovered.file_count, 260);
    assert_eq!(recovered.applied_seq, 389);
    let conn = rusqlite::Connection::open(workspace.findings_db_path()).unwrap();
    let count: i64 = conn
        .query_row("select count(*) from indexed_files", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 260);
    log.verify_chain().unwrap();
}

#[test]
fn cancellation_during_capture_publishes_no_index_events() {
    let (_root, workspace) = fixture();
    let canceled = Cell::new(false);
    assert!(index_workspace_snapshot_cancellable(
        &workspace,
        &mut |event| {
            if matches!(event, SourceIndexProgress::ReadFiles(1)) {
                canceled.set(true);
            }
        },
        &|| canceled.get()
    )
    .is_err());
    assert!(!workspace.event_log_dir().exists());
}

#[test]
fn incomplete_index_baseline_cannot_drop_unvisited_files_on_the_next_change() {
    let (root, workspace) = fixture();
    let canceled = Cell::new(false);
    assert!(index_workspace_snapshot_cancellable(
        &workspace,
        &mut |event| {
            if matches!(
                event,
                SourceIndexProgress::PersistedUpdates { completed: 128, .. }
            ) {
                canceled.set(true);
            }
        },
        &|| canceled.get()
    )
    .is_err());
    fs::write(root.path().join("owned-259.txt"), "Owned changed source\n").unwrap();
    let update = index_workspace_changes(
        &workspace,
        &[WorkspaceChange::FileChanged("owned-259.txt".into())],
    )
    .unwrap();
    assert_eq!(update.file_count(), Some(260));
    let WorkspaceIndexUpdate::Full(recovered) = update else {
        panic!("an incomplete projection requires full source capture");
    };
    assert_eq!(
        recovered.tree_hash,
        current_workspace_tree_hash(root.path()).unwrap()
    );
    assert_eq!(recovered.files.len(), 260);
}

#[test]
fn identity_only_index_baseline_cannot_drop_unchanged_files() {
    let (root, workspace) = fixture();
    index_workspace_snapshot(&workspace).unwrap();
    fs::write(root.path().join("owned-000.txt"), "Owned first change\n").unwrap();
    register_workspace_tree_identity(&workspace).unwrap();
    fs::write(root.path().join("owned-259.txt"), "Owned next change\n").unwrap();
    let update = index_workspace_changes(
        &workspace,
        &[WorkspaceChange::FileChanged("owned-259.txt".into())],
    )
    .unwrap();
    assert_eq!(update.file_count(), Some(260));
    let WorkspaceIndexUpdate::Full(recovered) = update else {
        panic!("identity registration is not a complete content index");
    };
    assert_eq!(
        recovered.tree_hash,
        current_workspace_tree_hash(root.path()).unwrap()
    );
    assert_eq!(recovered.files.len(), 260);
}
