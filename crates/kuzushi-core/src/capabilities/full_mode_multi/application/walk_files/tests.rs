use super::*;
use std::cell::Cell;
use std::path::PathBuf;

fn config(root: &std::path::Path) -> FullModeConfig {
    FullModeConfig {
        workspace_root: root.into(),
        ..Default::default()
    }
}

#[test]
fn shared_inventory_keeps_loose_files_deep_paths_and_ignored_boundaries_visible() {
    let root = tempfile::tempdir().unwrap();
    let mut deep = root.path().to_path_buf();
    for _ in 0..150 {
        deep.push("d");
    }
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(deep.join("owned.c"), "// inert\n").unwrap();
    std::fs::write(root.path().join("loose.c"), "// inert\n").unwrap();
    std::fs::create_dir(root.path().join("vendor")).unwrap();
    std::fs::write(root.path().join("vendor/omitted.c"), "// inert\n").unwrap();
    let result = walk_files(&config(root.path()), &mut |_| {}, &|| false).unwrap();
    assert_eq!(result.files.len(), 2);
    assert!(result.files.iter().any(|file| file.path == "loose.c"));
    assert!(result
        .coverage
        .excluded_paths
        .iter()
        .any(|row| row.path == "vendor"));
    assert!(!result.coverage.is_partial());
}

#[test]
fn explicit_scope_keeps_non_c_and_vendor_membership_without_an_inventory_walk() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("vendor")).unwrap();
    std::fs::write(root.path().join("vendor/owned.scala"), "// inert\n").unwrap();
    let mut cfg = config(root.path());
    cfg.scope_files = Some(vec!["vendor/owned.scala".into()]);
    let result = walk_files(&cfg, &mut |_| {}, &|| false).unwrap();
    assert_eq!(result.files[0].path, "vendor/owned.scala");
    assert_eq!(result.coverage.enumeration, "explicit-scope");
    assert!(result.coverage.inventory.is_none());
}

#[test]
fn metadata_reservation_omits_an_oversized_sparse_file_before_reading_it() {
    let root = tempfile::tempdir().unwrap();
    let file = std::fs::File::create(root.path().join("large.c")).unwrap();
    file.set_len(crate::workspace::MAX_REPOSITORY_INSPECTED_BYTES as u64 + 1)
        .unwrap();
    let mut cfg = config(root.path());
    cfg.scope_files = Some(vec!["large.c".into()]);
    let result = walk_files(&cfg, &mut |_| {}, &|| false).unwrap();
    assert!(result.files.is_empty());
    assert!(result.coverage.is_partial());
    assert_eq!(result.coverage.planning_read_bytes, 0);
    assert!(result.coverage.omitted_sources[0]
        .reason
        .contains("source byte planning limit"));
}

#[test]
fn aggregate_source_limit_and_file_limit_preserve_a_partial_plan() {
    let root = tempfile::tempdir().unwrap();
    for name in ["a.c", "b.c", "c.c"] {
        std::fs::write(root.path().join(name), "12345").unwrap();
    }
    let mut coverage = inventory::empty_coverage();
    coverage.max_source_bytes = 9;
    coverage.max_source_files = 2;
    let result = source_buckets::collect(
        &config(root.path()),
        vec!["a.c".into(), "b.c".into(), "c.c".into()],
        coverage,
        &mut |_| {},
        &|| false,
    )
    .unwrap();
    assert_eq!(result.files.len(), 1);
    assert_eq!(result.coverage.selected_source_bytes, 5);
    assert_eq!(result.coverage.omitted_sources.len(), 2);
    assert!(result.coverage.is_partial());
}

#[test]
fn cancellation_after_progress_keeps_work_and_prevents_execution() {
    let root = tempfile::tempdir().unwrap();
    for name in ["a.c", "b.c"] {
        std::fs::write(root.path().join(name), "// inert\n").unwrap();
    }
    let mut cfg = config(root.path());
    cfg.scope_files = Some(vec!["a.c".into(), "b.c".into()]);
    let stop = Cell::new(false);
    let plan =
        super::super::plan::plan_with_observer(&cfg, &mut |_| stop.set(true), &|| stop.get())
            .unwrap();
    assert!(plan.coverage.as_ref().unwrap().canceled);
    assert!(plan.ensure_execution_ready().is_err());
}

#[test]
fn long_lines_and_invalid_utf8_are_omissions_instead_of_invalid_windows() {
    let root = tempfile::tempdir().unwrap();
    let cap = crate::capabilities::full_mode_multi::MAX_FILE_BYTES;
    std::fs::write(root.path().join("line.c"), vec![b'x'; cap + 1]).unwrap();
    std::fs::write(
        root.path().join("invalid.c"),
        [255, b'\n'].repeat(cap / 2 + 1),
    )
    .unwrap();
    let mut cfg = config(root.path());
    cfg.scope_files = Some(vec!["line.c".into(), "invalid.c".into()]);
    let result = walk_files(&cfg, &mut |_| {}, &|| false).unwrap();
    assert!(result.files.is_empty());
    assert_eq!(result.coverage.omitted_sources.len(), 2);
    assert!(result
        .coverage
        .omitted_sources
        .iter()
        .any(|row| row.reason.contains("utf-8")));
    assert!(result.coverage.planning_read_bytes <= 2 * (cap + 1));
}

#[test]
fn truncated_inventory_cannot_authorize_execution_even_with_visible_files() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a.c"), "// inert\n").unwrap();
    let mut inventory = crate::workspace::build_repository_inventory(root.path()).unwrap();
    let inspection = inventory.inspection.as_mut().unwrap();
    inspection.enumeration_complete = Some(false);
    let (_, coverage) = inventory::inventory_paths(
        &config(root.path()),
        inventory,
        inventory::empty_coverage(),
        false,
    )
    .unwrap();
    assert!(coverage.enumeration_incomplete);
    assert!(coverage.is_partial());
}

#[cfg(unix)]
#[test]
fn shared_inventory_does_not_follow_directory_cycles_or_file_symlinks() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("owned.c"), "// inert\n").unwrap();
    std::os::unix::fs::symlink(root.path(), root.path().join("cycle")).unwrap();
    std::os::unix::fs::symlink(root.path().join("owned.c"), root.path().join("link.c")).unwrap();
    let result = walk_files(&config(root.path()), &mut |_| {}, &|| false).unwrap();
    assert_eq!(result.files.len(), 1);
    assert!(result
        .coverage
        .excluded_paths
        .iter()
        .any(|row| row.path == "cycle"));
}

#[test]
fn an_excessive_explicit_scope_fails_before_opening_paths() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = config(root.path());
    cfg.scope_files = Some(vec![
        PathBuf::from("missing.c");
        crate::workspace::MAX_REPOSITORY_ENTRIES + 1
    ]);
    assert!(format!(
        "{:#}",
        walk_files(&cfg, &mut |_| {}, &|| false).err().unwrap()
    )
    .contains("100000-entry"));
}
