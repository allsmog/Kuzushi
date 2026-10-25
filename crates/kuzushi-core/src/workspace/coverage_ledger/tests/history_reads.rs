use super::*;

#[test]
fn equal_timestamps_select_the_last_recorded_revision_across_modes() {
    let root = workspace_dir();
    let ledger = CoverageLedger::open(root.path()).unwrap();
    let mut first = baseline("root", WorkflowPhase::Scan, "older-sha", 100);
    first.mode = "first".into();
    let mut last = baseline("root", WorkflowPhase::Scan, "newer-sha", 100);
    last.mode = "second".into();
    last.run_id = "newer-run".into();
    ledger.record_baseline(&first).unwrap();
    ledger.record_baseline(&last).unwrap();
    assert_eq!(ledger.latest_baselines().unwrap(), vec![last.clone()]);
    drop(ledger);
    assert_eq!(
        CoverageLedger::open_if_exists(root.path())
            .unwrap()
            .unwrap()
            .latest_baselines()
            .unwrap(),
        vec![last]
    );
}

#[test]
fn later_imports_with_older_timestamps_do_not_replace_the_latest_revision() {
    let root = workspace_dir();
    let ledger = CoverageLedger::open(root.path()).unwrap();
    let newest = baseline("root", WorkflowPhase::Scan, "newest-sha", 200);
    ledger.record_baseline(&newest).unwrap();
    ledger
        .record_baseline(&baseline("root", WorkflowPhase::Scan, "old-import", 100))
        .unwrap();
    assert_eq!(ledger.latest_baselines().unwrap(), vec![newest]);
}

#[test]
fn historical_text_is_bounded_in_bytes_without_mutating_or_truncating_rows() {
    let root = workspace_dir();
    let ledger = CoverageLedger::open(root.path()).unwrap();
    for ts in [1, 2] {
        let mut row = baseline("root", WorkflowPhase::Scan, "owned-sha", ts);
        row.revision.branch = Some("é".repeat(2 * 1024 * 1024));
        ledger.record_baseline(&row).unwrap();
    }
    let result = ledger.all_baselines();
    assert!(
        result.is_err(),
        "Oversized history must fail without printing its payload"
    );
    let error = result.unwrap_err();
    assert!(error.to_string().contains("8388608-byte read limit"));
    assert_eq!(ledger.latest_baselines().unwrap()[0].ts_unix, 2);
    let rows: i64 = ledger
        .connection()
        .query_row("select count(*) from scan_baselines", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 2);
}

#[test]
fn one_oversized_latest_row_is_refused_by_the_same_read_guard() {
    let root = workspace_dir();
    let ledger = CoverageLedger::open(root.path()).unwrap();
    let mut row = baseline("root", WorkflowPhase::Scan, "owned-sha", 1);
    row.run_id = "x".repeat(8 * 1024 * 1024 + 1);
    ledger.record_baseline(&row).unwrap();
    let result = ledger.latest_baselines();
    assert!(
        result.is_err(),
        "Oversized row must fail without printing its payload"
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("8388608-byte read limit"));
}
