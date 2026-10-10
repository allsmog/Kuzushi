use super::*;

#[test]
fn initialized_ledger_reads_preserve_bytes_and_refuse_writes() {
    let root = workspace_dir();
    CoverageLedger::open(root.path())
        .unwrap()
        .record_baseline(&baseline(".", WorkflowPhase::Scan, "synthetic-sha", 1))
        .unwrap();
    let path = workspace_coverage_db_path(root.path());
    let before = fs::read(&path).unwrap();
    let ledger = CoverageLedger::open_if_exists(root.path())
        .unwrap()
        .unwrap();
    assert_eq!(ledger.latest_baselines().unwrap().len(), 1);
    assert!(ledger
        .record_baseline(&baseline(".", WorkflowPhase::Scan, "synthetic-sha", 2))
        .is_err());
    drop(ledger);
    assert_eq!(before, fs::read(path).unwrap());
}

#[test]
fn missing_reads_do_not_create_workspace_state() {
    let root = tempfile::tempdir().unwrap();
    assert!(CoverageLedger::open_if_exists(root.path())
        .unwrap()
        .is_none());
    assert!(!root.path().join(".kuzushi").exists());
}

#[test]
fn unsupported_or_incomplete_schema_is_refused_without_mutation() {
    for version in [0, 1, 2] {
        let root = workspace_dir();
        let path = workspace_coverage_db_path(root.path());
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE owned_sentinel(value TEXT);")
            .unwrap();
        conn.pragma_update(None, "user_version", version).unwrap();
        drop(conn);
        let before = fs::read(&path).unwrap();
        assert!(CoverageLedger::open_if_exists(root.path()).is_err());
        assert_eq!(before, fs::read(&path).unwrap());
    }
}

#[test]
fn excessive_baseline_history_is_refused_instead_of_truncated() {
    let root = workspace_dir();
    let ledger = CoverageLedger::open(root.path()).unwrap();
    let transaction = ledger.connection().unchecked_transaction().unwrap();
    for ts in 0..10_000 {
        ledger
            .record_baseline(&baseline(".", WorkflowPhase::Scan, "synthetic-sha", ts))
            .unwrap();
    }
    transaction.commit().unwrap();
    assert_eq!(ledger.all_baselines().unwrap().len(), 10_000);
    ledger
        .record_baseline(&baseline(".", WorkflowPhase::Scan, "synthetic-sha", 10_000))
        .unwrap();
    assert!(ledger
        .all_baselines()
        .unwrap_err()
        .to_string()
        .contains("10000-row read limit"));
    assert_eq!(ledger.latest_baselines().unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn read_only_ledger_refuses_an_outside_symlink() {
    let root = workspace_dir();
    let outside = workspace_dir();
    CoverageLedger::open(outside.path()).unwrap();
    let outside_path = workspace_coverage_db_path(outside.path());
    let before = fs::read(&outside_path).unwrap();
    std::os::unix::fs::symlink(&outside_path, workspace_coverage_db_path(root.path())).unwrap();
    assert!(CoverageLedger::open_if_exists(root.path()).is_err());
    assert_eq!(before, fs::read(outside_path).unwrap());
}
