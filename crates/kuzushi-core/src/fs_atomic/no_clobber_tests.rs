use super::write_new_atomic;

#[test]
fn a_new_artifact_never_replaces_existing_operator_bytes() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("draft.json");
    std::fs::write(&path, b"owned operator draft").unwrap();
    assert!(write_new_atomic(&path, "replacement").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"owned operator draft");
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn concurrent_new_artifact_writers_keep_one_complete_result() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("draft.json");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let writes = ["a".repeat(4096), "b".repeat(4096)];
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = writes
            .iter()
            .map(|text| {
                let barrier = barrier.clone();
                let path = &path;
                scope.spawn(move || {
                    barrier.wait();
                    write_new_atomic(path, text)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(writes.contains(&text));
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
#[cfg(unix)]
fn existing_symlink_and_its_target_stay_unchanged() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("operator.txt");
    let path = root.path().join("draft.json");
    std::fs::write(&target, "operator bytes").unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(write_new_atomic(&path, "replacement").is_err());
    assert!(std::fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "operator bytes");
}
