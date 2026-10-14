use super::*;

#[test]
fn total_read_allowance_keeps_observations_and_discloses_unread_remainder() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("a.env"),
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();
    fs::write(root.path().join("b.txt"), "x".repeat(100)).unwrap();
    let options = SecretScanOptions {
        max_total_bytes: 80,
        ..Default::default()
    };
    let report = scan_for_secrets(root.path(), &options, &Default::default()).unwrap();
    assert_eq!(report.files_scanned, 1);
    assert_eq!(report.findings.len(), 1);
    assert!(report.coverage_gaps.gaps[0]
        .reason
        .contains("total content read allowance"));
    assert_eq!(report.to_tool_json()["status"], "partial");
    let inspection = report.inspection.unwrap();
    assert!(inspection.content_bytes_reserved <= 80);
    assert!(inspection.content_bytes_reserved > 0);
}

#[test]
fn finding_cap_is_partial_for_whole_directory_and_even_a_single_selected_file() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("a.env"),
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();
    let options = SecretScanOptions {
        max_findings: 1,
        ..Default::default()
    };
    let report = scan_for_secrets(root.path(), &options, &Default::default()).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert!(report.coverage_gaps.gaps[0]
        .reason
        .contains("0 selected files"));
    assert_eq!(report.to_tool_json()["status"], "partial");
    assert!(report.to_tool_json()["data"]["inspection"].is_object());
}

#[test]
fn per_file_omission_is_partial_and_reserves_no_content_bytes() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("large.txt"), "x".repeat(128)).unwrap();
    let options = SecretScanOptions {
        max_file_bytes: 64,
        ..Default::default()
    };
    let report = scan_for_secrets(root.path(), &options, &Default::default()).unwrap();
    assert_eq!(report.files_skipped, 1);
    assert_eq!(report.files_scanned, 0);
    assert_eq!(
        report.inspection.as_ref().unwrap().content_bytes_reserved,
        0
    );
    assert_eq!(report.to_tool_json()["status"], "partial");
}

#[test]
fn exact_membership_uses_the_same_total_read_allowance_and_never_reads_other_files() {
    let root = tempfile::tempdir().unwrap();
    for name in ["a.txt", "b.txt", "other.txt"] {
        fs::write(root.path().join(name), "x".repeat(60)).unwrap();
    }
    let options = SecretScanOptions {
        max_total_bytes: 80,
        ..Default::default()
    };
    let report = scan_exact_files_with_options(
        root.path(),
        &["a.txt".into(), "b.txt".into()],
        &options,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(report.files_scanned, 1);
    assert!(report.coverage_gaps.gaps[0]
        .reason
        .contains("total content read allowance"));
    assert_eq!(report.inspection.as_ref().unwrap().traversal_entries, None);
    assert_eq!(report.inspection.unwrap().content_bytes_reserved, 61);
}

#[test]
fn content_reservations_refuse_overflow_and_do_not_expand_after_failure() {
    let mut budget = ContentBudget::new(10);
    budget.reserve(6).unwrap();
    assert!(budget.reserve(3).is_err());
    assert_eq!(budget.reserved, 7);
    assert!(budget.reserve(u64::MAX).is_err());
    assert_eq!(budget.reserved, 7);
}

#[test]
fn exact_membership_above_the_entry_allowance_is_refused_before_reading() {
    let root = tempfile::tempdir().unwrap();
    let options = SecretScanOptions {
        max_entries: 1,
        ..Default::default()
    };
    assert!(scan_exact_files_with_options(
        root.path(),
        &["a.txt".into(), "b.txt".into()],
        &options,
        &Default::default()
    )
    .unwrap_err()
    .to_string()
    .contains("membership exceeds"));
}

#[test]
fn cancellation_after_one_file_preserves_its_observation_and_marks_partial_coverage() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("a.env"),
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let options = SecretScanOptions::default();
    let cancel = ScanCancellation::default();
    let mut tally = SecretScanTally::default();
    let mut budget = ContentBudget::new(options.max_total_bytes);
    assert!(scan_next_file(
        &root_path,
        &root_path.join("a.env"),
        &options,
        &cancel,
        &mut tally,
        &mut budget,
        2
    ));
    cancel.cancel();
    assert!(!scan_next_file(
        &root_path,
        &root_path.join("b.env"),
        &options,
        &cancel,
        &mut tally,
        &mut budget,
        1
    ));
    tally.content_bytes_reserved = budget.reserved;
    let report = tally.into_report(&root_path, &options);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.files_scanned, 1);
    assert!(report.coverage_gaps.gaps[0]
        .reason
        .contains("1 selected files"));
    assert_eq!(report.to_tool_json()["status"], "partial");
}
