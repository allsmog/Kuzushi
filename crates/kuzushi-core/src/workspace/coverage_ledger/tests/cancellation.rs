use super::super::sweep::sweep_target_with_cancellation;
use super::*;
use crate::ScanCancellation;
use std::cell::Cell;

#[test]
fn cancellation_during_skip_writes_rolls_back_every_insert_and_allows_explicit_retry() {
    let root = temp_git_workspace().expect("Git is required for cancellation integration");
    let original = head_sha(root.path());
    let ledger = CoverageLedger::open(root.path()).unwrap();
    for phase in [WorkflowPhase::Map, WorkflowPhase::Scan] {
        ledger
            .record_baseline(&baseline("root", phase, &original, 100))
            .unwrap();
    }
    let before = ledger.all_baselines().unwrap();
    git(
        root.path(),
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "-m",
            "Owned metadata revision",
        ],
    );
    let report = sweep_target(root.path()).unwrap();
    let cancellation = ScanCancellation::default();
    let visited = Cell::new(0);
    let entries = report.entries.iter().inspect(|_| {
        visited.set(visited.get() + 1);
        if visited.get() == 2 {
            cancellation.cancel();
        }
    });
    let error =
        super::super::sweep::write_skips(root.path(), &report, entries, Some(&cancellation))
            .unwrap_err();
    assert!(error.to_string().contains("cancelled"));
    assert_eq!(visited.get(), 2);
    assert_eq!(ledger.all_baselines().unwrap(), before);
    assert_eq!(write_sweep_skips(root.path(), &report).unwrap(), 2);
    assert_eq!(ledger.all_baselines().unwrap().len(), before.len() + 2);
}

#[test]
fn canceled_ledger_read_and_sweep_do_not_create_or_change_history() {
    let root = temp_git_workspace().expect("Git is required for cancellation integration");
    let cancellation = ScanCancellation::default();
    cancellation.cancel();
    assert!(
        sweep_target_with_cancellation(root.path(), Some(&cancellation))
            .unwrap_err()
            .to_string()
            .contains("cancelled")
    );
    assert!(!workspace_coverage_db_path(root.path()).exists());
    let ledger = CoverageLedger::open(root.path()).unwrap();
    assert!(ledger
        .latest_baselines_with_cancellation(Some(&cancellation))
        .unwrap_err()
        .to_string()
        .contains("cancelled"));
    assert!(ledger.all_baselines().unwrap().is_empty());
}
