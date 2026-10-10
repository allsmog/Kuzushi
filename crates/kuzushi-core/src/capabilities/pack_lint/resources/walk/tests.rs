use super::super::LintLimits;
use super::*;
#[test]
fn one_entry_allowance_is_shared_across_walks() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("one"), "owned").unwrap();
    let resources = LintResources::new(
        temp.path(),
        LintLimits {
            entries: 1,
            ..LintLimits::default()
        },
        &|| false,
    );
    assert!(resources
        .walk(temp.path(), temp.path(), 5000, true, false)
        .is_empty());
    assert!(resources
        .walk(temp.path(), &temp.path().join("one"), 5000, true, false)
        .is_empty());
    assert_eq!(resources.coverage()["entriesExamined"], 1);
    assert!(resources.partial());
}

#[test]
fn deep_walk_uses_a_small_stack_and_excludes_hidden_entries() {
    let temp = tempfile::tempdir().unwrap();
    let mut path = temp.path().to_path_buf();
    for _ in 0..300 {
        path.push("d");
        std::fs::create_dir(&path).unwrap();
    }
    std::fs::write(path.join("source.rs"), "// owned").unwrap();
    std::fs::write(temp.path().join(".ignored"), "owned").unwrap();
    let root = temp.path().to_path_buf();
    let count = std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(move || {
            let resources = LintResources::new(&root, LintLimits::default(), &|| false);
            let files = resources.walk(&root, &root, 5000, true, true);
            assert!(!resources.partial());
            assert_eq!(resources.coverage()["ignoredHiddenEntries"], 1);
            files.len()
        })
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(count, 1);
}

#[cfg(unix)]
#[test]
fn symlink_cycles_external_links_and_parent_paths_are_excluded() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("owned"), "owned").unwrap();
    std::fs::write(outside.path().join("external"), "external").unwrap();
    std::os::unix::fs::symlink(temp.path(), temp.path().join("cycle")).unwrap();
    std::os::unix::fs::symlink(outside.path(), temp.path().join("external")).unwrap();
    let resources = LintResources::new(temp.path(), LintLimits::default(), &|| false);
    assert_eq!(
        resources
            .walk(temp.path(), temp.path(), 5000, true, false)
            .len(),
        1
    );
    assert!(resources
        .read(&temp.path().join("external/external"))
        .is_err());
    assert!(resources
        .walk(temp.path(), outside.path(), 5000, true, false)
        .is_empty());
    assert!(resources.partial());
}

#[test]
fn cancellation_and_zero_file_limit_never_visit_files() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("owned"), "owned").unwrap();
    let resources = LintResources::new(temp.path(), LintLimits::default(), &|| true);
    assert!(resources
        .walk(temp.path(), temp.path(), 5000, true, false)
        .is_empty());
    assert!(resources.read(&temp.path().join("owned")).is_err());
    assert_eq!(resources.coverage()["canceled"], true);
    assert_eq!(resources.coverage()["reservedReadBytes"], 0);
    let resources = LintResources::new(temp.path(), LintLimits::default(), &|| false);
    assert!(resources
        .walk(temp.path(), &temp.path().join("owned"), 0, true, false)
        .is_empty());
    assert_eq!(resources.coverage()["entriesExamined"], 0);
}
