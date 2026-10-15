use super::*;

fn owned_file(root: &Path, name: &str) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, "// Labeled owned metadata. Never executed.\n").unwrap();
}

#[test]
fn traversal_preserves_depth_first_order_and_loose_parent_files() {
    let root = tempfile::tempdir().unwrap();
    for name in ["z.rs", "service/z.rs", "service/a.rs", "a.rs"] {
        owned_file(root.path(), name);
    }
    let paths = collect_taint_iris_next_source_paths(root.path(), None).unwrap();
    assert_eq!(
        paths
            .iter()
            .map(|p| p.relative_path.as_str())
            .collect::<Vec<_>>(),
        ["a.rs", "service/a.rs", "service/z.rs", "z.rs"]
    );
}

#[test]
fn sampled_traversal_stays_a_stable_prefix_of_the_complete_inventory() {
    let root = tempfile::tempdir().unwrap();
    for name in ["a.rs", "nested/a.rs", "z.rs"] {
        owned_file(root.path(), name);
    }
    let full = collect_taint_iris_next_source_paths(root.path(), None).unwrap();
    let sample = collect_taint_iris_next_source_paths(root.path(), Some(2)).unwrap();
    assert_eq!(
        sample.iter().map(|p| &p.relative_path).collect::<Vec<_>>(),
        full[..2]
            .iter()
            .map(|p| &p.relative_path)
            .collect::<Vec<_>>()
    );
}

#[test]
fn wide_directory_limit_is_an_explicit_error() {
    let root = tempfile::tempdir().unwrap();
    for name in ["a.rs", "b.rs", "c.rs"] {
        owned_file(root.path(), name);
    }
    let error =
        collect_taint_iris_next_source_paths_with_limits(root.path(), None, 10, 2).unwrap_err();
    assert!(error.to_string().contains("entry walk limit"), "{error:#}");
}

#[test]
fn declared_cpp_extension_is_not_omitted_from_the_inventory() {
    let root = tempfile::tempdir().unwrap();
    owned_file(root.path(), "owned.cxx");
    let paths = collect_taint_iris_next_source_paths(root.path(), None).unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].language, "cpp");
}

#[cfg(unix)]
#[test]
fn symlink_cycles_and_external_files_are_excluded() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    owned_file(root.path(), "owned.rs");
    owned_file(outside.path(), "outside.rs");
    std::os::unix::fs::symlink(root.path(), root.path().join("cycle")).unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("outside.rs"),
        root.path().join("linked.rs"),
    )
    .unwrap();
    let paths = collect_taint_iris_next_source_paths(root.path(), None).unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].relative_path, "owned.rs");
}

#[test]
#[ignore = "Explicit isolated small-stack walk over owned directory metadata"]
fn deep_metadata_traversal_does_not_use_the_call_stack() {
    let root = tempfile::tempdir().unwrap();
    let mut deepest = root.path().to_path_buf();
    for _ in 0..160 {
        deepest.push("n");
        fs::create_dir(&deepest).unwrap();
    }
    owned_file(&deepest, "owned.rs");
    let path = root.path().to_path_buf();
    let paths = std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(move || collect_taint_iris_next_source_paths(&path, None))
        .unwrap()
        .join()
        .unwrap()
        .unwrap();
    assert_eq!(paths.len(), 1);
}
