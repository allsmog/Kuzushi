use super::*;
const ID: &str = "00000000-0000-4000-8000-000000000001";

#[test]
fn private_atomic_checkpoint_is_target_isolated_and_bounded() {
    let root = tempfile::tempdir().unwrap();
    let store = EditorCheckpointStore::for_study_drafts(root.path().join(".kuzushi/v3/sessions"));
    store.write(root.path(), ID, b"first").unwrap();
    store.write(root.path(), ID, b"second").unwrap();
    assert_eq!(store.read(root.path()).unwrap()[0].bytes, b"second");
    assert!(store.read(&root.path().join("other")).unwrap().is_empty());
    assert!(store
        .write(root.path(), ID, &vec![0; MAX_EDITOR_CHECKPOINT_BYTES + 1])
        .is_err());
    assert_eq!(
        store.read_record(root.path(), ID).unwrap().unwrap().bytes,
        b"second"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let directory = store.directory(root.path()).unwrap();
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(directory.join(format!("{ID}.json")))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn capacity_and_interrupted_temporary_file_keep_published_data() {
    let root = tempfile::tempdir().unwrap();
    let store = EditorCheckpointStore::for_study_drafts(root.path().join(".kuzushi/v3/sessions"));
    store.write(root.path(), ID, b"published").unwrap();
    let directory = store.directory(root.path()).unwrap();
    fs::write(directory.join("interrupted.tmp"), b"incomplete").unwrap();
    for n in 0..126 {
        fs::write(directory.join(format!("{n}.tmp")), b"").unwrap();
    }
    assert!(store
        .write(root.path(), "00000000-0000-4000-8000-000000000002", b"new")
        .is_err());
    store.write(root.path(), ID, b"updated").unwrap();
    assert_eq!(store.read(root.path()).unwrap()[0].bytes, b"updated");
}

#[cfg(unix)]
#[test]
fn symlinks_and_nonregular_records_are_rejected_without_modification() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let store = EditorCheckpointStore::for_study_drafts(root.path().join(".kuzushi/v3/sessions"));
    store.write(root.path(), ID, b"original").unwrap();
    let path = store
        .directory(root.path())
        .unwrap()
        .join(format!("{ID}.json"));
    fs::remove_file(&path).unwrap();
    let outside = root.path().join("outside");
    fs::write(&outside, b"retained").unwrap();
    symlink(&outside, &path).unwrap();
    assert!(store.read(root.path()).is_err());
    assert!(store.write(root.path(), ID, b"overwrite").is_err());
    assert_eq!(fs::read(&outside).unwrap(), b"retained");
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(store.read_record(root.path(), ID).is_err());
}
