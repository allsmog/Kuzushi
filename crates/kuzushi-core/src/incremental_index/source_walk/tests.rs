use super::*;
use crate::{incremental_index::*, WorkspaceTarget};
use std::cell::Cell;

#[test]
fn deep_source_identity_uses_a_small_stack_and_matches_blob_indexing() {
    let root = tempfile::tempdir().unwrap();
    let mut leaf = root.path().to_path_buf();
    for _ in 0..300 {
        leaf.push("a");
        fs::create_dir(&leaf).unwrap();
    }
    fs::write(leaf.join("leaf.rs"), "pub fn leaf() {}\n").unwrap();
    let path = root.path().to_path_buf();
    let hash = std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(move || current_workspace_tree_hash(path).unwrap())
        .unwrap()
        .join()
        .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let indexed = index_workspace_snapshot(&workspace).unwrap();
    assert_eq!(indexed.tree_hash, hash);
    assert_eq!(indexed.file_count, 1);
    assert_eq!(
        register_workspace_tree_identity(&workspace)
            .unwrap()
            .tree_hash,
        hash
    );
    // Remove from the leaves so fixture cleanup does not introduce recursion.
    fs::remove_file(leaf.join("leaf.rs")).unwrap();
    for _ in 0..300 {
        fs::remove_dir(&leaf).unwrap();
        leaf.pop();
    }
}

#[test]
fn empty_directory_breadth_consumes_the_entry_budget() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..12 {
        fs::create_dir(root.path().join(format!("dir-{index}"))).unwrap();
    }
    let mut files = 0;
    let error = walk_with_limit(root.path(), 8, &|| false, &mut |event| {
        if matches!(event, SourceWalkEvent::File(_)) {
            files += 1;
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.to_string().contains("8-entry safety limit"));
    assert_eq!(files, 0);
}

#[test]
fn directory_progress_can_cancel_without_hashing_a_file_or_registering_a_snapshot() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..40 {
        fs::create_dir(root.path().join(format!("dir-{index}"))).unwrap();
    }
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let progress = Cell::new(0);
    let error = register_workspace_tree_identity_cancellable(
        &workspace,
        &mut |files| {
            assert_eq!(files, 0);
            progress.set(progress.get() + 1);
        },
        &|| progress.get() >= 5,
    )
    .unwrap_err();
    assert!(error.to_string().contains("canceled"));
    assert_eq!(progress.get(), 5);
    assert!(!workspace.findings_db_path().exists());
}

#[cfg(unix)]
#[test]
fn symlink_cycles_and_external_files_are_not_traversed() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(root.path().join("root.rs"), "pub fn root() {}\n").unwrap();
    fs::write(outside.path().join("external.rs"), "external content\n").unwrap();
    let before = current_workspace_tree_hash(root.path()).unwrap();
    symlink(root.path(), root.path().join("cycle")).unwrap();
    symlink(outside.path(), root.path().join("external")).unwrap();
    symlink(
        outside.path().join("external.rs"),
        root.path().join("external.rs"),
    )
    .unwrap();
    assert_eq!(current_workspace_tree_hash(root.path()).unwrap(), before);
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    assert_eq!(
        index_workspace_snapshot(&workspace).unwrap().tree_hash,
        before
    );
}

#[cfg(unix)]
#[test]
fn queued_directory_replaced_with_an_external_symlink_fails_closed() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let child = root.path().join("child");
    fs::create_dir(&child).unwrap();
    fs::write(outside.path().join("external.rs"), "external content\n").unwrap();
    let mut events = 0;
    let error = walk_source_files(root.path(), &|| false, &mut |event| {
        assert!(!matches!(event, SourceWalkEvent::File(_)));
        events += 1;
        if events == 2 {
            fs::remove_dir(&child)?;
            symlink(outside.path(), &child)?;
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.to_string().contains("source directory changed"));
}

#[test]
fn public_identity_observer_remains_one_callback_per_hashed_file() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("empty")).unwrap();
    fs::write(root.path().join("a.rs"), "a\n").unwrap();
    fs::write(root.path().join("b.rs"), "b\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut observations = Vec::new();
    register_workspace_tree_identity_with_observer(&workspace, &mut |files| {
        observations.push(files)
    })
    .unwrap();
    assert_eq!(observations, vec![1, 2]);
}

#[test]
fn source_file_read_checks_cancellation_between_chunks() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("source.rs");
    fs::write(&path, vec![b'x'; 192 * 1024]).unwrap();
    let checks = Cell::new(0);
    let error = read_indexed_file_cancellable(&path, &|| {
        checks.set(checks.get() + 1);
        checks.get() >= 3
    })
    .unwrap_err();
    assert!(error.to_string().contains("canceled"));
    assert_eq!(checks.get(), 3);
}

#[test]
fn file_growth_cannot_read_past_the_remaining_snapshot_allowance() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("source.rs");
    fs::write(&path, [b'x'; 32]).unwrap();
    let mut budget = IndexBudget::with_limits(2, 33);
    let checks = Cell::new(0);
    let error = read_budgeted_source_file(&path, &mut budget, &|| {
        checks.set(checks.get() + 1);
        if checks.get() == 2 {
            fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(&[b'y'; 100])
                .unwrap();
        }
        false
    })
    .unwrap_err();
    assert!(error.to_string().contains("33-byte safety limit"));
    assert_eq!(budget.bytes, 0);
}

#[test]
fn aggregate_source_bytes_are_reserved_before_the_next_file_is_opened() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("source.rs");
    fs::write(&path, [b'x'; 32]).unwrap();
    let mut budget = IndexBudget::with_limits(2, 63);
    read_budgeted_source_file(&path, &mut budget, &|| false).unwrap();
    let reads = Cell::new(0);
    let error = read_budgeted_source_file(&path, &mut budget, &|| {
        reads.set(reads.get() + 1);
        false
    })
    .unwrap_err();
    assert!(error.to_string().contains("63-byte safety limit"));
    assert_eq!(reads.get(), 0);
    assert_eq!(budget.bytes, 32);
}
