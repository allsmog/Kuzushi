use super::*;
use crate::run_artifacts::write_run_summary;
use std::cell::Cell;

fn write_scan(root: &Path, id: &str, started: u64) {
    let mut summary = RunSummary::running(
        id,
        "tool",
        Some("sast:scan".into()),
        root.display().to_string(),
    )
    .complete();
    summary.started_at_unix = started;
    write_run_summary(root, &summary).unwrap();
}

#[test]
fn usage_catalogue_is_bounded_and_named_older_evidence_remains_readable() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..102 {
        write_scan(
            root.path(),
            &format!("scan-{index:03}"),
            1_791_244_800 + index,
        );
    }
    let catalogue = load_scan_usage_catalogue(root.path(), &|| false)
        .unwrap()
        .unwrap();
    assert_eq!(catalogue.inspected_entries, 100);
    assert_eq!(catalogue.run_ids.len(), 100);
    assert!(catalogue.history_limit_reached);
    assert!(!catalogue.run_ids.contains(&"scan-000".into()));
    let evidence = load_named_scan_usage(root.path(), "scan-000").unwrap();
    assert!(evidence.provider_usage.is_none() && evidence.cost_usd.is_none());
}

#[test]
fn catalogue_cancel_before_or_during_loading_never_publishes_partial_choices() {
    let root = tempfile::tempdir().unwrap();
    assert!(load_scan_usage_catalogue(root.path(), &|| true)
        .unwrap()
        .is_none());
    assert!(!root.path().join(".kuzushi").exists());
    write_scan(root.path(), "completed", 1_791_244_800);
    let checks = Cell::new(0);
    let cancelled = || {
        checks.set(checks.get() + 1);
        checks.get() > 1
    };
    assert!(load_scan_usage_catalogue(root.path(), &cancelled)
        .unwrap()
        .is_none());
}

#[test]
fn incomplete_runs_and_malformed_metadata_are_not_calibration_choices() {
    let root = tempfile::tempdir().unwrap();
    let summary = RunSummary::running(
        "unfinished",
        "tool",
        Some("sast:scan".into()),
        root.path().display().to_string(),
    );
    write_run_summary(root.path(), &summary).unwrap();
    write_scan(root.path(), "malformed", 1_791_244_800);
    std::fs::write(
        root.path().join(".kuzushi/v3/runs/malformed/run.json"),
        "{ labeled malformed metadata",
    )
    .unwrap();
    assert!(load_named_scan_usage(root.path(), "unfinished").is_err());
    assert!(load_scan_usage_catalogue(root.path(), &|| false)
        .unwrap()
        .unwrap()
        .run_ids
        .is_empty());
    assert!(load_named_scan_usage(root.path(), "../outside").is_err());
}

#[cfg(unix)]
#[test]
fn named_usage_refuses_symlinked_run_directories() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join(".kuzushi/v3/runs")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join(".kuzushi/v3/runs/linked"))
        .unwrap();
    assert!(load_named_scan_usage(root.path(), "linked").is_err());
}
