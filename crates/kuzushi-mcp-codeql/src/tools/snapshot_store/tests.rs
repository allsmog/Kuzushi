use super::session_root::{TEST_OWNER_LOCK, TEST_SESSION_PREFIX};
use super::*;

#[cfg(unix)]
fn executable_bundle(root: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let launcher = root.join("source/bin/codeql");
    std::fs::create_dir_all(launcher.parent().unwrap()).unwrap();
    std::fs::write(&launcher, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir_all(root.join("source/lib")).unwrap();
    std::fs::write(root.join("source/lib/helper"), "one").unwrap();
    launcher
}

fn database(root: &Path) -> PathBuf {
    let database = root.join("database");
    std::fs::create_dir_all(database.join("db-cpp")).unwrap();
    std::fs::write(
        database.join("codeql-database.yml"),
        "primaryLanguage: cpp\n",
    )
    .unwrap();
    std::fs::write(database.join("db-cpp/data"), "one").unwrap();
    database
}

#[test]
fn startup_removes_abandoned_session_but_preserves_live_session() {
    let parent = tempfile::tempdir().unwrap();
    let abandoned = parent
        .path()
        .join(format!("{TEST_SESSION_PREFIX}abandoned"));
    std::fs::create_dir(&abandoned).unwrap();
    std::fs::write(abandoned.join(TEST_OWNER_LOCK), "").unwrap();
    let live = SnapshotSessionRoot::create(parent.path()).unwrap();
    let live_path = live.path().to_path_buf();
    let second = SnapshotSessionRoot::create(parent.path()).unwrap();

    assert!(!abandoned.exists());
    assert!(live_path.exists());
    assert!(second.path().exists());
}

#[test]
fn owned_session_is_removed_on_drop() {
    let parent = tempfile::tempdir().unwrap();
    let path = {
        let root = SnapshotSessionRoot::create(parent.path()).unwrap();
        root.path().to_path_buf()
    };

    assert!(!path.exists());
}

#[test]
fn default_snapshot_parent_is_stable_for_the_operator() {
    assert_eq!(
        default_snapshot_parent().unwrap(),
        default_snapshot_parent().unwrap()
    );
    #[cfg(windows)]
    assert!(default_snapshot_parent()
        .unwrap()
        .ends_with("kuzushi/codeql-snapshots-v1"));
}

#[cfg(windows)]
#[test]
fn windows_lock_open_does_not_follow_a_reparse_point() {
    use std::os::windows::fs::symlink_file;

    let parent = tempfile::tempdir().unwrap();
    let target = parent.path().join("target");
    let link = parent.path().join("owner.lock");
    std::fs::write(&target, "outside").unwrap();
    if symlink_file(&target, &link).is_err() {
        return;
    }

    let error = session_root::open_lock_for_test(&link).unwrap_err();

    assert!(error.to_string().contains("reparse point"));
}

#[cfg(unix)]
#[tokio::test]
async fn codeql_cache_reuses_and_replaces_one_owned_snapshot() {
    let parent = tempfile::tempdir().unwrap();
    let store = CodeqlSnapshotStore::new_in(parent.path().join("sessions")).unwrap();
    let launcher = executable_bundle(parent.path());
    let first = store.current(&launcher).await.unwrap();
    let reused = store.current(&launcher).await.unwrap();
    assert_eq!(first.launcher, reused.launcher);

    std::fs::write(parent.path().join("source/lib/helper"), "two").unwrap();
    let replaced = store.current(&launcher).await.unwrap();

    assert_ne!(first.launcher, replaced.launcher);
    assert!(first.is_cancelled());
    assert_eq!(
        std::fs::read(replaced.bundle_root.join("lib/helper")).unwrap(),
        b"two"
    );
    std::fs::write(parent.path().join("source/lib/helper"), "tri").unwrap();
    let bounded = store.current(&launcher).await.err().unwrap().to_string();
    assert!(bounded.contains("still retiring"), "{bounded}");
    drop(first);
    drop(reused);
    assert_eq!(
        std::fs::read(
            store
                .current(&launcher)
                .await
                .unwrap()
                .bundle_root
                .join("lib/helper")
        )
        .unwrap(),
        b"tri"
    );
}

#[tokio::test]
async fn database_cache_reuses_receipt_and_replaces_changed_content() {
    let parent = tempfile::tempdir().unwrap();
    let store = CodeqlSnapshotStore::new_in(parent.path().join("sessions")).unwrap();
    let source = database(parent.path());
    let first_revision = database_identity::database_identity(&source).unwrap();
    let first = store.database(&source, &first_revision).await.unwrap();
    let reused = store.database(&source, &first_revision).await.unwrap();
    assert_eq!(first.directory, reused.directory);

    std::fs::write(source.join("db-cpp/data"), "two").unwrap();
    let second_revision = database_identity::database_identity(&source).unwrap();
    let replaced = store.database(&source, &second_revision).await.unwrap();

    assert_ne!(first.directory, replaced.directory);
    assert!(first.is_cancelled());
    assert_eq!(
        std::fs::read(replaced.directory.join("db-cpp/data")).unwrap(),
        b"two"
    );
    std::fs::write(source.join("db-cpp/data"), "tri").unwrap();
    let third_revision = database_identity::database_identity(&source).unwrap();
    let bounded = store
        .database(&source, &third_revision)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(bounded.contains("still retiring"), "{bounded}");
    drop(first);
    drop(reused);
    assert_eq!(
        std::fs::read(
            store
                .database(&source, &third_revision)
                .await
                .unwrap()
                .directory
                .join("db-cpp/data")
        )
        .unwrap(),
        b"tri"
    );
}

#[tokio::test]
async fn concurrent_database_replacements_cannot_overwrite_a_live_retirement() {
    let parent = tempfile::tempdir().unwrap();
    let store = Arc::new(CodeqlSnapshotStore::new_in(parent.path().join("sessions")).unwrap());
    let initial_source = database(&parent.path().join("initial"));
    let initial_revision = database_identity::database_identity(&initial_source).unwrap();
    let initial = store
        .database(&initial_source, &initial_revision)
        .await
        .unwrap();
    let first_source = database(&parent.path().join("first"));
    let second_source = database(&parent.path().join("second"));
    let first_revision = database_identity::database_identity(&first_source).unwrap();
    let second_revision = database_identity::database_identity(&second_source).unwrap();
    let gate = store.database_build_gate.lock().await;
    let first = spawn_database_request(&store, first_source, first_revision);
    let second = spawn_database_request(&store, second_source, second_revision);
    tokio::task::yield_now().await;
    drop(gate);

    let outcomes = [first.await.unwrap(), second.await.unwrap()];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_err()).count(),
        1
    );
    assert!(outcomes
        .iter()
        .filter_map(|outcome| outcome.as_ref().err())
        .any(|error| error.to_string().contains("still retiring")));
    assert!(initial.is_cancelled());
}

fn spawn_database_request(
    store: &Arc<CodeqlSnapshotStore>,
    source: PathBuf,
    revision: String,
) -> tokio::task::JoinHandle<Result<DatabaseExecutionSnapshot>> {
    let store = Arc::clone(store);
    tokio::spawn(async move { store.database(&source, &revision).await })
}
