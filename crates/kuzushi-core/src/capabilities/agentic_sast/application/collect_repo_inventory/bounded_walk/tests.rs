use super::*;
use std::cell::Cell;

fn options(files: usize, bytes: usize) -> AgenticSastInput {
    let mut input = AgenticSastInput::from_tool_input(&json!({})).unwrap();
    input.max_inventory_files = files;
    input.max_bytes_per_file = bytes;
    input
}

#[test]
fn wide_preparation_has_one_global_entry_budget_and_reports_its_prefix() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..30 {
        fs::write(
            root.path().join(format!("file-{index:02}.rs")),
            "source text",
        )
        .unwrap();
    }
    let entries = Cell::new(0);
    let result =
        collect_bounded_inventory(root.path(), &options(80, 4), 5, &|| Ok(()), &mut |value| {
            entries.set(value)
        })
        .unwrap();
    assert_eq!(result.coverage.enumerated_entries, 5);
    assert_eq!(entries.get(), 5);
    assert_eq!(result.snippets.len(), 5);
    assert_eq!(result.coverage.snippet_bytes, 20);
    assert_eq!(result.coverage.max_file_read_bytes, 4097);
    assert_eq!(result.coverage.reserved_read_bytes, 5 * 4097);
    assert!(result.coverage.truncation.unwrap().contains("entry limit"));
}

#[test]
fn binary_and_failed_candidate_reads_consume_the_conservative_content_allowance() {
    let root = tempfile::tempdir().unwrap();
    let binary = root.path().join("binary.rs");
    let missing = root.path().join("missing.rs");
    fs::write(&binary, [0u8; 8000]).unwrap();
    let options = options(80, 64);
    let mut progress = |_| {};
    let mut walk = InventoryWalk::new(root.path(), &options, 1000, &|| Ok(()), &mut progress);
    walk.result.coverage.max_read_bytes = 2 * 4097;
    walk.add_file(&binary, true);
    walk.add_file(&missing, true);
    assert!(walk.result.snippets.is_empty());
    assert_eq!(walk.result.coverage.reserved_read_bytes, 2 * 4097);
    walk.add_file(&binary, true);
    assert!(walk.result.coverage.read_limit_reached);
    assert!(walk.full());
    assert_eq!(walk.result.coverage.reserved_read_bytes, 2 * 4097);
    assert!(walk
        .result
        .coverage
        .truncation
        .unwrap()
        .contains("content-read allowance"));
}

#[test]
fn file_limit_discloses_remaining_preparation_without_more_reads() {
    let root = tempfile::tempdir().unwrap();
    for file in ["a.rs", "b.rs", "c.rs"] {
        fs::write(root.path().join(file), "source text").unwrap();
    }
    let result =
        collect_bounded_inventory(root.path(), &options(2, 4), 100, &|| Ok(()), &mut |_| {})
            .unwrap();
    assert_eq!(
        result
            .snippets
            .iter()
            .map(|row| row.0.as_str())
            .collect::<Vec<_>>(),
        vec!["a.rs", "b.rs"]
    );
    assert_eq!(result.coverage.snippet_bytes, 8);
    assert!(result.coverage.truncation.unwrap().contains("file limit"));
}

#[test]
fn deep_preparation_keeps_parent_files_without_recursive_calls() {
    let root = tempfile::tempdir().unwrap();
    let mut deep = root.path().to_path_buf();
    for _ in 0..200 {
        deep.push("d");
        fs::create_dir(&deep).unwrap();
    }
    fs::write(deep.join("leaf.rs"), "source").unwrap();
    fs::write(root.path().join("root.rs"), "source").unwrap();
    let result = collect_bounded_inventory(
        root.path(),
        &options(80, 2048),
        1000,
        &|| Ok(()),
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(result.snippets.len(), 2);
    assert!(result.snippets.iter().any(|row| row.0 == "root.rs"));
    assert!(result.coverage.truncation.is_none());
}

#[test]
fn cancellation_is_checked_during_directory_enumeration() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..50 {
        fs::write(root.path().join(format!("file-{index}.rs")), "source").unwrap();
    }
    let probes = Cell::new(0);
    let enumerated = Cell::new(0);
    let error = collect_bounded_inventory(
        root.path(),
        &options(80, 2048),
        1000,
        &|| {
            probes.set(probes.get() + 1);
            anyhow::ensure!(probes.get() < 7, "operator canceled preparation");
            Ok(())
        },
        &mut |value| enumerated.set(value),
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("operator canceled"));
    assert_eq!(enumerated.get(), 5);
}

#[cfg(unix)]
#[test]
fn symlink_cycles_are_not_followed_and_vendor_source_policy_is_preserved() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("third_party")).unwrap();
    fs::create_dir(root.path().join("node_modules")).unwrap();
    fs::write(root.path().join("third_party/component.rs"), "source").unwrap();
    fs::write(root.path().join("node_modules/ignored.rs"), "source").unwrap();
    std::os::unix::fs::symlink(root.path(), root.path().join("cycle")).unwrap();
    let result = collect_bounded_inventory(
        root.path(),
        &options(80, 2048),
        1000,
        &|| Ok(()),
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(
        result
            .snippets
            .iter()
            .map(|row| row.0.as_str())
            .collect::<Vec<_>>(),
        vec!["third_party/component.rs"]
    );
    assert_eq!(result.coverage.ignored_entries, 1);
    assert_eq!(result.coverage.skipped_entries, 1);
}
