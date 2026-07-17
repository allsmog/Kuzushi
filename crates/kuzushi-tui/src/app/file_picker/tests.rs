use super::*;
use std::fs;

#[test]
fn workspace_file_candidates_skip_state_and_dependency_dirs() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("README.md"), "readme").unwrap();
    fs::create_dir(tmp.path().join(".kuzushi")).unwrap();
    fs::write(tmp.path().join(".kuzushi").join("state.json"), "{}").unwrap();
    fs::create_dir(tmp.path().join("node_modules")).unwrap();
    fs::write(tmp.path().join("node_modules").join("dep.js"), "x").unwrap();

    let index = workspace_file_candidates(tmp.path(), 100);

    assert_eq!(index.values, vec!["README.md".to_string()]);
    assert!(!index.is_truncated());
}

#[test]
fn million_candidate_stream_stops_at_allocation_budgets() {
    let consumed = std::cell::Cell::new(0);
    let budget = FileDiscoveryBudget {
        retained_results: 37,
        entry_visits: 101,
        depth: 4,
        path_bytes: 1024 * 1024,
    };
    let candidates = (0..1_000_000).map(|index| {
        consumed.set(consumed.get() + 1);
        format!("src/file-{index:07}.rs")
    });

    let index = synthetic_file_candidates(candidates, budget);

    assert_eq!(consumed.get(), budget.entry_visits);
    assert_eq!(index.entries_visited, budget.entry_visits);
    assert_eq!(index.values.len(), budget.retained_results);
    assert!(index
        .limits_reached
        .contains(&FileCompletionLimit::EntryVisits));
    assert!(index
        .limits_reached
        .contains(&FileCompletionLimit::RetainedResults));
    assert!(index.values.windows(2).all(|pair| pair[0] <= pair[1]));
}

#[test]
fn path_byte_budget_stops_before_retaining_unbounded_names() {
    let budget = FileDiscoveryBudget {
        retained_results: 100,
        entry_visits: 100,
        depth: 4,
        path_bytes: 16,
    };

    let index = synthetic_file_candidates(
        [
            "short.rs".to_string(),
            "a-name-that-is-too-long.rs".to_string(),
        ]
        .into_iter(),
        budget,
    );

    assert_eq!(index.values, vec!["short.rs".to_string()]);
    assert!(index.path_bytes_observed <= budget.path_bytes);
    assert!(index
        .limits_reached
        .contains(&FileCompletionLimit::PathBytes));
}

#[test]
fn directory_traversal_observes_cancellation_between_chunks() {
    let tmp = tempfile::tempdir().unwrap();
    for index in 0..(FILE_PICKER_DIRECTORY_CHUNK * 3) {
        fs::write(tmp.path().join(format!("file-{index:04}.rs")), "x").unwrap();
    }
    let checks = std::cell::Cell::new(0);

    let index = workspace_file_candidates_cancellable(tmp.path(), 5_000, || {
        checks.set(checks.get() + 1);
        checks.get() > 1
    });

    assert!(index.is_none());
    assert_eq!(checks.get(), 2);
}

#[test]
fn depth_budget_is_reported_as_partial_index_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let first = tmp.path().join("one");
    let second = first.join("two");
    fs::create_dir_all(&second).unwrap();
    fs::write(second.join("deep.rs"), "x").unwrap();
    let budget = FileDiscoveryBudget {
        retained_results: 100,
        entry_visits: 100,
        depth: 1,
        path_bytes: 1024,
    };

    let index = FileDiscovery::new(tmp.path(), budget)
        .run(|| false)
        .expect("not canceled");

    assert!(index.values.is_empty());
    assert!(index.limits_reached.contains(&FileCompletionLimit::Depth));
    assert!(index.truncation_hint().is_some());
}

#[test]
fn pasted_workspace_files_accept_absolute_quoted_paths_inside_root() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("docs");
    fs::create_dir(&dir).unwrap();
    let file = dir.join("design note.md");
    fs::write(&file, "notes").unwrap();

    let pasted = format!("\"{}\"", file.display());

    assert_eq!(
        pasted_workspace_files(&pasted, tmp.path()),
        Some(vec!["docs/design note.md".to_string()])
    );
}

#[test]
fn pasted_workspace_files_reject_paths_outside_root() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();

    assert_eq!(
        pasted_workspace_files(&outside.path().display().to_string(), root.path()),
        None
    );
}
