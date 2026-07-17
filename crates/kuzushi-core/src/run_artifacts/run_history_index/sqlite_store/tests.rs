use super::*;
use crate::run_artifacts::run_history_index::retention::RetentionBuilder;

#[test]
fn compatibility_offsets_are_small_and_cursor_pages_continue() {
    let target = tempfile::tempdir().unwrap();
    let entries = (0..=1_100_u64)
        .map(|index| RunHistoryIndexEntry {
            run_id: format!("run-{index:06}"),
            started_at_unix: Some(index),
            issue: None,
        })
        .collect::<Vec<_>>();
    let policy = RetentionPolicy::default();
    let retained = retained_history(entries, policy);

    let stamp = capture_directory_stamp(target.path()).unwrap();
    replace_index(target.path(), &retained, policy, 1, stamp).unwrap();
    assert!(read_index_window(target.path(), MAX_COMPATIBILITY_OFFSET + 1, 1).is_err());
    let first = read_index_after(target.path(), None, 2).unwrap();
    let second = read_index_after(target.path(), first.next_cursor.as_ref(), 2).unwrap();

    assert_eq!(first.entries[0].run_id, "run-001100");
    assert_eq!(first.entries[1].run_id, "run-001099");
    assert_eq!(second.entries[0].run_id, "run-001098");
    assert_eq!(second.entries[1].run_id, "run-001097");
}

#[test]
fn replacement_leaves_no_sqlite_sidecars() {
    let target = tempfile::tempdir().unwrap();
    let policy = RetentionPolicy::default();
    let retained = retained_history(Vec::new(), policy);
    let stamp = capture_directory_stamp(target.path()).unwrap();
    replace_index(target.path(), &retained, policy, 1, stamp).unwrap();

    let state_root = super::super::super::checked_run_history_index_path(target.path())
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let names = std::fs::read_dir(state_root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert!(!names.iter().any(|name| {
        name.ends_with("-journal") || name.ends_with("-wal") || name.ends_with("-shm")
    }));
}

#[test]
fn external_directory_during_count_is_not_blessed() {
    let target = tempfile::tempdir().unwrap();
    let policy = RetentionPolicy::default();
    let retained = retained_history(Vec::new(), policy);
    let stamp = capture_directory_stamp(target.path()).unwrap();
    replace_index(target.path(), &retained, policy, 1, stamp).unwrap();
    let runs = super::super::super::checked_runs_root(target.path()).unwrap();
    std::fs::create_dir_all(runs.join("run-owned")).unwrap();
    let hook = database::external_mkdir_test_hook_path(target.path()).unwrap();
    std::fs::write(&hook, "run-external\n").unwrap();

    let error = upsert_missing_run(target.path(), "run-owned").unwrap_err();

    assert!(error.to_string().contains("run-history directory"));
    assert!(runs.join("run-external").is_dir());
    let connection = database::open_index(target.path(), false).unwrap();
    let total: i64 = connection
        .query_row(
            "SELECT canonical_total FROM run_history_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(total, 0);
}

fn retained_history(
    entries: Vec<RunHistoryIndexEntry>,
    policy: RetentionPolicy,
) -> RetainedHistory {
    let mut builder = RetentionBuilder::new(policy).unwrap();
    for entry in entries {
        builder.push(entry).unwrap();
    }
    builder.finish().unwrap()
}
