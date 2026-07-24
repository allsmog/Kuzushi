use super::secure_tree::SecureDirectory;
use super::tree_copy::copy_entry_for_test;
use super::*;
use std::ffi::OsStr;

#[test]
fn promotion_rejects_symlinks_inside_a_reported_database() {
    let workspace = tempfile::tempdir().unwrap();
    let isolated = tempfile::tempdir().unwrap();
    let destination = workspace.path().join(".kuzushi/codeql-db");
    fs::create_dir_all(destination.parent().unwrap()).unwrap();
    make_valid_database(isolated.path());
    #[cfg(unix)]
    std::os::unix::fs::symlink("codeql-database.yml", isolated.path().join("alias")).unwrap();

    #[cfg(unix)]
    assert!(promote_database(
        workspace.path(),
        isolated.path(),
        &destination,
        DestinationState::Missing,
    )
    .is_err());
    assert!(!destination.exists());
}

#[test]
fn failed_preflight_preserves_non_database_output() {
    let workspace = tempfile::tempdir().unwrap();
    let destination = workspace.path().join(".kuzushi/codeql-db");
    fs::create_dir_all(&destination).unwrap();
    fs::write(destination.join("important.txt"), "keep").unwrap();

    assert!(inspect_destination(&destination).is_err());
    assert_eq!(
        fs::read_to_string(destination.join("important.txt")).unwrap(),
        "keep"
    );
}

#[test]
fn promotion_rejects_destination_changed_after_preflight() {
    let workspace = tempfile::tempdir().unwrap();
    let isolated = tempfile::tempdir().unwrap();
    let destination = workspace.path().join(".kuzushi/codeql-db");
    fs::create_dir_all(destination.parent().unwrap()).unwrap();
    fs::create_dir(&destination).unwrap();
    make_valid_database(&destination);
    make_valid_database(isolated.path());
    let expected = inspect_destination(&destination).unwrap();
    fs::write(
        destination.join("codeql-database.yml"),
        "primaryLanguage: javascript\n",
    )
    .unwrap();

    let error = promote_database(workspace.path(), isolated.path(), &destination, expected)
        .unwrap_err()
        .to_string();

    assert!(error.contains("destination changed"), "{error}");
    assert_eq!(
        fs::read_to_string(destination.join("codeql-database.yml")).unwrap(),
        "primaryLanguage: javascript\n"
    );
}

#[test]
fn destination_identity_detects_nested_same_size_rewrite() {
    let workspace = tempfile::tempdir().unwrap();
    let isolated = tempfile::tempdir().unwrap();
    let destination = workspace.path().join(".kuzushi/codeql-db");
    fs::create_dir_all(destination.parent().unwrap()).unwrap();
    fs::create_dir(&destination).unwrap();
    make_valid_database(&destination);
    make_valid_database(isolated.path());
    let nested = destination.join("db-cpp/cache/chunk.bin");
    fs::create_dir_all(nested.parent().unwrap()).unwrap();
    fs::write(&nested, b"AAAA").unwrap();
    let expected = inspect_destination(&destination).unwrap();

    fs::write(&nested, b"BBBB").unwrap();
    let actual = inspect_destination(&destination).unwrap();

    assert_ne!(actual, expected);
    let error = promote_database(workspace.path(), isolated.path(), &destination, expected)
        .unwrap_err()
        .to_string();
    assert!(error.contains("destination changed"), "{error}");
    assert_eq!(fs::read(&nested).unwrap(), b"BBBB");
}

#[test]
fn promotion_returns_the_identity_of_the_staged_tree() {
    let workspace = tempfile::tempdir().unwrap();
    let isolated = tempfile::tempdir().unwrap();
    let destination = workspace.path().join(".kuzushi/codeql-db");
    fs::create_dir_all(destination.parent().unwrap()).unwrap();
    make_valid_database(isolated.path());
    fs::write(isolated.path().join("db-cpp/chunk.bin"), b"AAAA").unwrap();

    let promoted = promote_database(
        workspace.path(),
        isolated.path(),
        &destination,
        DestinationState::Missing,
    )
    .unwrap();

    assert_eq!(promoted, database_identity(&destination).unwrap());
    fs::write(destination.join("db-cpp/chunk.bin"), b"BBBB").unwrap();
    assert_ne!(promoted, database_identity(&destination).unwrap());
}

#[cfg(unix)]
#[test]
fn copy_rejects_file_swapped_to_symlink_after_enumeration() {
    use std::os::unix::fs::symlink;

    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    let victim = source.path().join("chunk.bin");
    fs::write(&victim, b"approved").unwrap();
    let opened = SecureDirectory::open(source.path()).unwrap();
    assert!(opened
        .entry_names(super::limits::MAX_DATABASE_ENTRIES as usize)
        .unwrap()
        .iter()
        .any(|name| name == "chunk.bin"));
    fs::remove_file(&victim).unwrap();
    symlink(outside.path(), &victim).unwrap();

    let error =
        copy_entry_for_test(&opened, OsStr::new("chunk.bin"), destination.path()).unwrap_err();

    assert!(
        format!("{error:#}").contains("symlinked database"),
        "{error:#}"
    );
    assert!(!destination.path().join("chunk.bin").exists());
}

#[test]
fn database_identity_includes_provenance_bytes() {
    let database = tempfile::tempdir().unwrap();
    make_valid_database(database.path());
    let before = database_identity(database.path()).unwrap();
    let provenance = database
        .path()
        .join(super::super::provenance::CODEQL_PROVENANCE_FILE);
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&provenance).unwrap()).unwrap();
    value["generation"] = serde_json::Value::String(uuid::Uuid::new_v4().to_string());
    fs::write(&provenance, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    let after = database_identity(database.path()).unwrap();

    assert_ne!(after, before);
}

#[test]
fn database_identity_frames_directory_boundaries() {
    let nested = tempfile::tempdir().unwrap();
    fs::create_dir(nested.path().join("a")).unwrap();
    fs::write(nested.path().join("a/b"), b"b").unwrap();
    fs::write(nested.path().join("a/c"), b"c").unwrap();
    let flattened = tempfile::tempdir().unwrap();
    fs::create_dir(flattened.path().join("a")).unwrap();
    fs::write(flattened.path().join("a/b"), b"b").unwrap();
    fs::write(flattened.path().join("c"), b"c").unwrap();

    assert_ne!(
        database_identity(nested.path()).unwrap(),
        database_identity(flattened.path()).unwrap()
    );
}

fn make_valid_database(path: &Path) {
    fs::write(path.join("codeql-database.yml"), "primaryLanguage: cpp\n").unwrap();
    fs::create_dir(path.join("db-cpp")).unwrap();
    let binding = crate::remediation::patch::RepositorySourceBinding {
        commit: "0".repeat(40),
        target_scope: ".".to_string(),
    };
    super::super::provenance::write_codeql_database_provenance(path, &binding, "cpp").unwrap();
}
