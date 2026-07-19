use super::*;

#[test]
fn identity_changes_for_same_size_content() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("entry");
    std::fs::write(&file, "one").unwrap();
    let first = database_identity(temp.path()).unwrap();

    std::fs::write(&file, "two").unwrap();
    let second = database_identity(temp.path()).unwrap();

    assert_ne!(first, second);
}

#[test]
fn preflight_rejects_total_content_above_the_promotion_bound() {
    let temp = tempfile::tempdir().unwrap();
    for name in ["first", "second"] {
        std::fs::File::create(temp.path().join(name))
            .unwrap()
            .set_len(MAX_DATABASE_IDENTITY_BYTES / 2 + 1)
            .unwrap();
    }

    let error = database_identity(temp.path()).unwrap_err().to_string();

    assert!(error.contains("promotion byte limit"), "{error}");
}

#[test]
fn enumeration_reads_only_remaining_capacity_plus_one() {
    let temp = tempfile::tempdir().unwrap();
    for name in ["one", "two", "three"] {
        std::fs::write(temp.path().join(name), name).unwrap();
    }
    let capability = ReadRootCapability::new([temp.path().to_path_buf()]).unwrap();
    let directory = capability.authorize_directory(temp.path()).unwrap();

    let error = bounded_children(&directory, 2).unwrap_err().to_string();

    assert!(error.contains("file-count limit"), "{error}");
}

#[test]
fn copied_database_receipt_matches_the_preauthenticated_identity() {
    let source = tempfile::tempdir().unwrap();
    std::fs::create_dir(source.path().join("db-cpp")).unwrap();
    std::fs::write(
        source.path().join("codeql-database.yml"),
        "primaryLanguage: cpp\n",
    )
    .unwrap();
    std::fs::write(source.path().join("db-cpp/data"), b"authenticated bytes").unwrap();
    let destination = tempfile::tempdir().unwrap();
    let expected = database_identity(source.path()).unwrap();

    let copied = copy_database(source.path(), destination.path()).unwrap();

    assert_eq!(copied, expected);
    assert_eq!(
        std::fs::read(destination.path().join("db-cpp/data")).unwrap(),
        b"authenticated bytes"
    );
}

#[cfg(any(unix, windows))]
#[test]
fn database_walker_never_accepts_a_swapped_nested_subset() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("database");
    let child = database.join("child");
    let retained = temp.path().join("retained-child");
    std::fs::create_dir_all(&child).unwrap();
    std::fs::write(child.join("trusted-a"), "trusted-a").unwrap();
    std::fs::write(child.join("trusted-b"), "trusted-b").unwrap();
    let capability = ReadRootCapability::new([temp.path().to_path_buf()]).unwrap();
    let directory = capability.authorize_directory(&database).unwrap();
    let entry = bounded_children(&directory, 4)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let expected = hash_test_entry(&directory, &entry).unwrap();

    std::fs::rename(&child, &retained).unwrap();
    std::fs::create_dir(&child).unwrap();
    std::fs::write(child.join("decoy"), "decoy").unwrap();
    let swapped = hash_test_entry(&directory, &entry);
    std::fs::remove_dir_all(&child).unwrap();
    std::fs::rename(&retained, &child).unwrap();

    match swapped {
        Ok(actual) => assert_eq!(actual, expected, "the retained child must be hashed"),
        Err(error) => {
            let message = format!("{error:#}");
            assert!(
                message.contains("directory entry") || message.contains("directory revision"),
                "unexpected error: {error:#}"
            );
        }
    }
    assert!(directory.verify_revision_unchanged().is_err());
}

#[cfg(any(unix, windows))]
#[test]
fn database_revision_receipts_reject_a_restored_same_directory_subset() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("database");
    let child_path = database.join("child");
    let omitted = child_path.join("trusted-b");
    let retained = temp.path().join("retained-b");
    std::fs::create_dir_all(&child_path).unwrap();
    std::fs::write(child_path.join("trusted-a"), "trusted-a").unwrap();
    std::fs::write(&omitted, "trusted-b").unwrap();
    let capability = ReadRootCapability::new([temp.path().to_path_buf()]).unwrap();
    let root = capability.authorize_directory(&database).unwrap();
    let child_entry = root.entries(4).unwrap().into_iter().next().unwrap();

    std::fs::rename(&omitted, &retained).unwrap();
    let AuthorizedChild::Directory(child) = root.open_child(&child_entry).unwrap() else {
        panic!("child token did not open a directory");
    };
    let mut budget = IdentityBudget::default();
    let mut revisions = AuthorizedDirectoryRevisions::new(&child, entry_limit().unwrap()).unwrap();
    let mut hasher = blake3::Hasher::new();
    hash_directory(
        &child,
        Path::new("child"),
        None,
        1,
        &mut budget,
        &mut revisions,
        &mut hasher,
    )
    .unwrap();
    std::fs::rename(&retained, &omitted).unwrap();

    let error = revisions.verify_all_unchanged().unwrap_err();
    assert!(
        format!("{error:#}").contains("directory revision"),
        "unexpected error: {error:#}"
    );
}

fn hash_test_entry(
    directory: &AuthorizedDirectory,
    entry: &AuthorizedDirectoryEntry,
) -> Result<String> {
    let mut budget = IdentityBudget::default();
    let mut revisions = AuthorizedDirectoryRevisions::new(directory, entry_limit()?)?;
    let mut hasher = blake3::Hasher::new();
    hash_entry(
        directory,
        Path::new(""),
        entry,
        None,
        0,
        &mut budget,
        &mut revisions,
        &mut hasher,
    )?;
    revisions.verify_all_unchanged()?;
    Ok(hasher.finalize().to_hex().to_string())
}
