use super::*;
use std::cell::Cell;

fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn recorded(id: &str, verified: bool) -> String {
    json!({"event":"recorded","finding_id":id,"verified":verified}).to_string()
}

#[test]
fn missing_roots_and_missing_index_are_distinct_from_an_empty_index() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");
    assert!(!workspace(&missing, &|| Ok(())).unwrap().initialized);
    assert!(index(&missing, &|| Ok(())).unwrap().is_none());
    assert!(index(root.path(), &|| Ok(())).unwrap().is_none());
    write(root.path(), "findings-index.jsonl", "\n");
    assert_eq!(index(root.path(), &|| Ok(())).unwrap().unwrap().total, 0);
}

#[test]
fn markers_are_sorted_metadata_without_any_execution() {
    let root = tempfile::tempdir().unwrap();
    for path in [
        "workspace.json",
        "data/sinks.jsonl",
        "targets/c/z/harness.cpp",
        "targets/c/a/harness.cpp",
        "bin/z/fuzzer",
        "targets/c/a/.localfuzz/workorder.json",
    ] {
        write(root.path(), path, "Owned inert marker. Never executed.\n");
    }
    let result = workspace(root.path(), &|| Ok(())).unwrap();
    assert!(result.initialized && result.sinks_present);
    assert_eq!(result.targets, ["a", "z"]);
    assert_eq!(result.built, ["z"]);
    assert_eq!(result.workorders, ["a"]);
}

#[test]
fn latest_recorded_flag_wins_and_bad_rows_are_counted() {
    let body = [
        recorded("a", true),
        recorded("b", true),
        recorded("a", false),
        "{invalid".into(),
        "{}".into(),
        "{\"event\":\"classified\"}".into(),
    ]
    .join("\n");
    let result = fold_counts(&body, &|| Ok(())).unwrap();
    assert_eq!(
        (result.total, result.verified, result.malformed_rows),
        (2, 1, 2)
    );
}

#[test]
fn row_cap_includes_ignored_and_malformed_rows() {
    let body = "{\"event\":\"classified\"}\n".repeat(MAX_ENTRIES);
    assert_eq!(fold_counts(&body, &|| Ok(())).unwrap().total, 0);
    let error = fold_counts(&(body + "invalid"), &|| Ok(())).err().unwrap();
    assert!(error.to_string().contains("10000-row inspection limit"));
}

#[test]
fn directory_cap_counts_all_entries() {
    let root = tempfile::tempdir().unwrap();
    let entries = root.path().join("targets/c");
    std::fs::create_dir_all(&entries).unwrap();
    for index in 0..=MAX_ENTRIES {
        std::fs::write(entries.join(index.to_string()), "").unwrap();
    }
    let error = workspace(root.path(), &|| Ok(())).err().unwrap();
    assert!(error.to_string().contains("10000-entry inspection limit"));
}

#[test]
fn byte_cap_and_non_utf8_content_are_errors() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("findings-index.jsonl");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(MAX_INDEX_BYTES as u64 + 1).unwrap();
    assert!(index(root.path(), &|| Ok(())).is_err());
    std::fs::write(path, [0xff]).unwrap();
    assert!(index(root.path(), &|| Ok(())).is_err());
}

#[test]
fn nonregular_markers_and_indexes_are_errors() {
    let root = tempfile::tempdir().unwrap();
    for name in ["workspace.json", "findings-index.jsonl"] {
        std::fs::create_dir(root.path().join(name)).unwrap();
    }
    assert!(workspace(root.path(), &|| Ok(())).is_err());
    assert!(index(root.path(), &|| Ok(())).is_err());
    assert!(workspace(&root.path().join("workspace.json/missing"), &|| Ok(())).is_ok());
    write(root.path(), "root-is-file", "inert");
    assert!(workspace(&root.path().join("root-is-file"), &|| Ok(())).is_err());
}

#[test]
fn cancellation_is_checked_before_io_and_between_rows_and_entries() {
    let root = tempfile::tempdir().unwrap();
    let canceled = || anyhow::bail!("owned cancellation");
    assert!(workspace(root.path(), &canceled).is_err());
    assert!(index(root.path(), &canceled).is_err());
    let count = Cell::new(0);
    let active = || {
        count.set(count.get() + 1);
        anyhow::ensure!(count.get() < 3, "owned cancellation");
        Ok(())
    };
    assert!(fold_counts(&"{}\n".repeat(10), &active).is_err());
    assert_eq!(count.get(), 3);
    count.set(0);
    for name in ["a", "b", "c"] {
        write(root.path(), &format!("targets/c/{name}"), "");
    }
    assert!(workspace(root.path(), &active).is_err());
    assert_eq!(count.get(), 3);
}

#[cfg(unix)]
#[test]
fn linked_markers_and_target_directories_are_refused() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    write(outside.path(), "marker", "Owned excluded marker");
    std::os::unix::fs::symlink(
        outside.path().join("marker"),
        root.path().join("workspace.json"),
    )
    .unwrap();
    assert!(workspace(root.path(), &|| Ok(())).is_err());
    std::fs::remove_file(root.path().join("workspace.json")).unwrap();
    std::fs::create_dir_all(root.path().join("targets/c")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("targets/c/linked")).unwrap();
    assert!(workspace(root.path(), &|| Ok(())).is_err());
    std::os::unix::fs::symlink(
        outside.path().join("marker"),
        root.path().join("findings-index.jsonl"),
    )
    .unwrap();
    assert!(index(root.path(), &|| Ok(())).is_err());
    assert_eq!(
        std::fs::read_to_string(outside.path().join("marker")).unwrap(),
        "Owned excluded marker"
    );
}
