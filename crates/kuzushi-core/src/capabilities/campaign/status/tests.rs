use super::*;
use crate::findings::{DismissReason, Finding, Severity};

#[test]
fn workspace_trend_counts_repeated_identity_once_after_human_fp() {
    let root = tempfile::tempdir().unwrap();
    let store = FindingStore::open(root.path().join("ledger.sqlite3")).unwrap();
    let row = Finding::new_tool(
        "fixture",
        "owned.marker",
        "owned.rs",
        1,
        None,
        Severity::Low,
        "Owned counter fixture",
    );
    store
        .record_run_started("first", root.path(), "completed")
        .unwrap();
    store.insert_finding("first", &row).unwrap();
    store
        .record_run_started("second", root.path(), "completed")
        .unwrap();
    let later = store.insert_finding("second", &row).unwrap();
    store
        .append_dismissal(
            later,
            DismissReason::FalsePositive,
            "Owned fixture routing",
            "operator",
        )
        .unwrap();
    let metrics = workspace_review_metrics(Some(&store), Default::default());
    assert_eq!(
        (
            metrics.decided_findings,
            metrics.confirmed_findings,
            metrics.rejected_false_positives
        ),
        (1, 0, 1)
    );
    assert!(!metrics.decisions_unreadable);
}
