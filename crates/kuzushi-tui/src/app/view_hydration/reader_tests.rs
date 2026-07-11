use super::reader::FsViewArtifactReader;
use super::*;

fn map_state(target: &Path) -> bool {
    let ViewHydrationValue::MapArtifacts(built) =
        FsViewArtifactReader.read(target, &ViewHydrationKey::MapArtifacts)
    else {
        panic!("map hydration returned the wrong value type");
    };
    built
}

#[test]
fn map_hydration_rejects_a_directory_at_a_file_artifact_path() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join(".kuzushi/context-snapshot.json")).unwrap();

    assert!(!map_state(temp.path()));
}

#[cfg(unix)]
#[test]
fn map_hydration_rejects_symlinked_artifacts() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::create_dir_all(temp.path().join(".kuzushi")).unwrap();
    symlink(
        outside.path(),
        temp.path().join(".kuzushi/context-snapshot.json"),
    )
    .unwrap();

    assert!(!map_state(temp.path()));
}

#[cfg(unix)]
#[test]
fn map_hydration_rejects_a_symlinked_state_parent() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("context-snapshot.json"), "{}").unwrap();
    symlink(outside.path(), temp.path().join(".kuzushi")).unwrap();

    assert!(!map_state(temp.path()));
}

#[test]
fn map_hydration_accepts_a_real_codeql_database_directory() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join(".kuzushi/codeql-db")).unwrap();

    assert!(map_state(temp.path()));
}

#[test]
fn mismatched_hydration_values_leave_the_key_retryable() {
    let temp = tempfile::tempdir().unwrap();
    let key = ViewHydrationKey::LatestRunPointer;
    let mut cache = WorkbenchCache::default();
    cache.mark_view_hydration_loading(temp.path(), std::slice::from_ref(&key));

    cache.apply_view_hydration(ViewHydrationResult {
        target: temp.path().to_path_buf(),
        key: key.clone(),
        value: ViewHydrationValue::TargetBase("wrong value".to_string()),
    });

    assert!(cache.view_hydration_needed(temp.path(), &key));
}

#[test]
fn source_hydration_rejects_paths_outside_the_target() {
    let target = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    let value = FsViewArtifactReader.read(
        target.path(),
        &ViewHydrationKey::SourceFile {
            path: outside.path().to_path_buf(),
        },
    );

    let ViewHydrationValue::SourceFile(result) = value else {
        panic!("source hydration returned the wrong value type");
    };
    assert!(result.is_err());
}

#[test]
fn source_hydration_rejects_oversized_files() {
    let target = tempfile::tempdir().unwrap();
    let source = target.path().join("large.rs");
    let file = std::fs::File::create(&source).unwrap();
    file.set_len((2 * 1024 * 1024 + 1) as u64).unwrap();
    let value = FsViewArtifactReader.read(
        target.path(),
        &ViewHydrationKey::SourceFile { path: source },
    );

    let ViewHydrationValue::SourceFile(result) = value else {
        panic!("source hydration returned the wrong value type");
    };
    assert!(result.is_err());
}

#[cfg(unix)]
#[test]
fn directory_hydration_rejects_symlinked_prompt_roots() {
    use std::os::unix::fs::symlink;

    let target = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret.md"), "secret").unwrap();
    let prompts = target.path().join(".kuzushi/prompts");
    std::fs::create_dir_all(&prompts).unwrap();
    let prompt_root = prompts.join("sast");
    symlink(outside.path(), &prompt_root).unwrap();
    let value = FsViewArtifactReader.read(
        target.path(),
        &ViewHydrationKey::DirectoryListing { path: prompt_root },
    );

    assert!(matches!(
        value,
        ViewHydrationValue::DirectoryListing(DirectoryListingState::Unreadable)
    ));
}
