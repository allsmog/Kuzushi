use super::*;

#[test]
fn iterative_traversal_preserves_lexical_depth_first_order() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("a")).unwrap();
    fs::write(root.path().join("a/first.txt"), "hello").unwrap();
    fs::write(root.path().join("z.txt"), "hello").unwrap();
    let mut files = Vec::new();
    let mut gaps = CoverageGaps::default();
    assert_eq!(
        collect(
            root.path(),
            root.path(),
            &Default::default(),
            &Default::default(),
            &mut files,
            &mut gaps
        )
        .unwrap(),
        3
    );
    assert_eq!(
        files,
        vec![
            root.path().join("a/first.txt").canonicalize().unwrap(),
            root.path().join("z.txt").canonicalize().unwrap()
        ]
    );
    assert!(gaps.is_empty());
}

#[test]
fn entry_allowance_bounds_wide_trees_and_reports_unknown_remaining_coverage() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..10 {
        fs::write(root.path().join(format!("{index}.txt")), "hello").unwrap();
    }
    let mut files = Vec::new();
    let mut gaps = CoverageGaps::default();
    let options = SecretScanOptions {
        max_entries: 2,
        ..Default::default()
    };
    assert_eq!(
        collect(
            root.path(),
            root.path(),
            &options,
            &Default::default(),
            &mut files,
            &mut gaps
        )
        .unwrap(),
        2
    );
    assert_eq!(files.len(), 2);
    assert!(gaps.gaps[0].reason.contains("remaining directory entries"));
}

#[test]
fn deeply_nested_tree_uses_a_finite_stack_and_ignored_directories_are_not_descended() {
    let root = tempfile::tempdir().unwrap();
    let mut leaf = root.path().to_path_buf();
    for _ in 0..250 {
        leaf.push("d");
        fs::create_dir(&leaf).unwrap();
    }
    fs::write(leaf.join("leaf.txt"), "hello").unwrap();
    fs::create_dir(root.path().join("node_modules")).unwrap();
    fs::write(root.path().join("node_modules/ignored.txt"), "hello").unwrap();
    let mut files = Vec::new();
    let mut gaps = CoverageGaps::default();
    assert_eq!(
        collect(
            root.path(),
            root.path(),
            &Default::default(),
            &Default::default(),
            &mut files,
            &mut gaps
        )
        .unwrap(),
        252
    );
    assert_eq!(files, vec![leaf.join("leaf.txt").canonicalize().unwrap()]);
    assert!(gaps.is_empty());
}

#[test]
fn cancellation_stops_before_collecting_source_or_entering_directories() {
    let root = tempfile::tempdir().unwrap();
    let cancel = ScanCancellation::default();
    cancel.cancel();
    let mut files = Vec::new();
    let mut gaps = CoverageGaps::default();
    assert!(collect(
        root.path(),
        root.path(),
        &Default::default(),
        &cancel,
        &mut files,
        &mut gaps
    )
    .unwrap_err()
    .to_string()
    .contains("cancelled during traversal"));
    assert!(files.is_empty());
}

#[cfg(unix)]
#[test]
fn symlink_cycles_and_external_source_are_never_followed() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("outside.txt"), "hello").unwrap();
    fs::write(root.path().join("inside.txt"), "hello").unwrap();
    std::os::unix::fs::symlink(root.path(), root.path().join("cycle")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("outside")).unwrap();
    let mut files = Vec::new();
    let mut gaps = CoverageGaps::default();
    collect(
        root.path(),
        root.path(),
        &Default::default(),
        &Default::default(),
        &mut files,
        &mut gaps,
    )
    .unwrap();
    assert_eq!(
        files,
        vec![root.path().join("inside.txt").canonicalize().unwrap()]
    );
    assert!(gaps.is_empty());
}
