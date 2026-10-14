use super::*;

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    (directory, root)
}

fn small_budget(entries: usize, bytes: u64) -> InputBudget {
    InputBudget {
        remaining_entries: entries,
        remaining_bytes: bytes,
        deadline: Instant::now() + Duration::from_secs(10),
    }
}

#[test]
fn bounded_snapshot_preserves_sorted_legacy_content_digests() {
    let (_directory, root) = fixture();
    std::fs::create_dir(root.join("nested")).unwrap();
    std::fs::write(root.join("nested/z"), "second").unwrap();
    std::fs::write(root.join("a"), "first").unwrap();
    let rows = tree_rows(&root, &root, &mut small_budget(3, 11), 16).unwrap();
    assert_eq!(
        rows,
        vec![
            (
                "a".into(),
                crate::run_lifecycle::sha256_content_digest(b"first")
            ),
            (
                "nested/z".into(),
                crate::run_lifecycle::sha256_content_digest(b"second")
            ),
        ]
    );
}

#[test]
fn deep_tree_is_inspected_iteratively_and_keeps_the_leaf() {
    let (_directory, root) = fixture();
    let mut leaf = root.clone();
    for _ in 0..400 {
        leaf.push("d");
        std::fs::create_dir(&leaf).unwrap();
    }
    std::fs::write(leaf.join("data"), "leaf").unwrap();
    let rows = tree_rows(&root, &root, &mut small_budget(401, 4), 4).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].0.ends_with("/data"));
}

#[test]
fn wide_tree_cannot_publish_a_partial_identity() {
    let (_directory, root) = fixture();
    for index in 0..8 {
        std::fs::write(root.join(index.to_string()), "x").unwrap();
    }
    let error = tree_rows(&root, &root, &mut small_budget(3, 8), 1).unwrap_err();
    assert!(error.to_string().contains("entry limit"), "{error}");
}

#[test]
fn shared_byte_budget_covers_multiple_input_trees_and_executables() {
    let (_directory, root) = fixture();
    let cache = root.join("cache");
    std::fs::create_dir(&cache).unwrap();
    std::fs::write(cache.join("graph"), "123456").unwrap();
    std::fs::write(root.join("binary"), "12345").unwrap();
    let mut budget = small_budget(3, 10);
    assert!(tree_rows(&root, &cache, &mut budget, 6).is_ok());
    let error = executable_digest(&root.join("binary"), &mut budget).unwrap_err();
    assert!(format!("{error:#}").contains("read limit"));
}

#[test]
fn oversized_and_expired_inputs_refuse_without_a_hash() {
    let (_directory, root) = fixture();
    std::fs::write(root.join("large"), "12345").unwrap();
    let error = tree_rows(&root, &root, &mut small_budget(1, 5), 4).unwrap_err();
    assert!(format!("{error:#}").contains("file exceeds"));
    assert!(error.to_string().contains("large"));
    let mut expired = small_budget(1, 5);
    expired.deadline = Instant::now() - Duration::from_secs(1);
    assert!(tree_rows(&root, &root, &mut expired, 5)
        .unwrap_err()
        .to_string()
        .contains("deadline"));
}

#[cfg(unix)]
#[test]
fn symlink_cycles_roots_and_file_aliases_are_refused() {
    let (_directory, root) = fixture();
    let real = root.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::write(real.join("file"), "x").unwrap();
    std::os::unix::fs::symlink(&real, root.join("linked-root")).unwrap();
    assert!(tree_rows(&root, &root.join("linked-root"), &mut small_budget(3, 3), 3).is_err());
    std::os::unix::fs::symlink(&real, real.join("cycle")).unwrap();
    assert!(tree_rows(&root, &real, &mut small_budget(3, 3), 3).is_err());
    std::fs::remove_file(real.join("cycle")).unwrap();
    std::os::unix::fs::symlink(real.join("file"), real.join("alias")).unwrap();
    assert!(tree_rows(&root, &real, &mut small_budget(3, 3), 3).is_err());
    let absent = root.join("absent");
    assert!(
        optional_tree_rows(&root, &absent, &mut small_budget(3, 3), 3)
            .unwrap()
            .is_none()
    );
    std::os::unix::fs::symlink(root.join("never-created"), &absent).unwrap();
    assert!(optional_tree_rows(&root, &absent, &mut small_budget(3, 3), 3).is_err());
}
