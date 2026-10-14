use super::*;

fn root_with_file(content: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("fixture.env"), content).unwrap();
    root
}

fn options(entries: usize, bytes: u64, findings: usize) -> SecretScanOptions {
    SecretScanOptions {
        max_entries: entries,
        max_total_bytes: bytes,
        max_findings: findings,
        ..Default::default()
    }
}

#[test]
fn directory_roots_share_content_reservations_and_original_limits() {
    let first = root_with_file(&"#".repeat(900));
    let second = root_with_file(&"#".repeat(900));
    let scanner = ConfiguredSecretScanScanner::new(options(100, 1024, 10));
    let cancel = ScanCancellation::default();
    scanner.scan_artifacts(first.path(), &cancel).unwrap();
    let output = scanner.scan_artifacts(second.path(), &cancel).unwrap();
    assert!(!output.scan_errors.is_empty());
    let receipts = scanner.inspection_receipts();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[1]["inspection"]["maxTotalBytes"], 123);
    assert_eq!(receipts[1]["configuredLimits"]["maxTotalBytes"], 1024);
    assert_eq!(receipts[1]["totals"]["contentBytesReserved"], 901);
    assert_eq!(receipts[1]["totals"]["entriesReserved"], 2);
}

#[test]
fn exact_files_consume_entry_allowance_before_another_root() {
    let first = root_with_file("# Labeled inert fixture\n");
    let second = root_with_file("# Labeled inert fixture\n");
    let scanner = ConfiguredSecretScanScanner::new(options(1, 1024, 10));
    let files = ["fixture.env".to_string()];
    let cancel = ScanCancellation::default();
    scanner
        .scan_exact_files(first.path(), &files, &cancel)
        .unwrap();
    let error = scanner
        .scan_exact_files(second.path(), &files, &cancel)
        .unwrap_err();
    assert!(error.to_string().contains("entry allowance reached"));
    assert_eq!(scanner.inspection_receipts().len(), 1);
    assert_eq!(
        scanner.inspection_receipts()[0]["totals"]["entriesReserved"],
        1
    );
}

#[test]
fn finding_cap_preserves_signal_and_refuses_further_roots() {
    let first = root_with_file(
        "# Public example, no active credential\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
    );
    let second = root_with_file("# Labeled inert fixture\n");
    let scanner = ConfiguredSecretScanScanner::new(options(100, 1024, 1));
    let cancel = ScanCancellation::default();
    let output = scanner.scan_artifacts(first.path(), &cancel).unwrap();
    assert_eq!(output.findings.len(), 1);
    assert!(!output.scan_errors.is_empty());
    assert!(scanner
        .scan_artifacts(second.path(), &cancel)
        .unwrap_err()
        .to_string()
        .contains("finding allowance reached"));
    assert_eq!(scanner.inspection_receipts()[0]["totals"]["findings"], 1);
}

#[test]
fn accounting_failure_cannot_partly_update_remaining_allowance() {
    let root = root_with_file("# Fixture\n");
    let report = scan_for_secrets(
        root.path(),
        &options(10, 1024, 10),
        &ScanCancellation::default(),
    )
    .unwrap();
    let mut state = InspectionState {
        entries_left: 10,
        bytes_left: 0,
        findings_left: 10,
        receipts: Vec::new(),
    };
    assert!(state.record(&report, None, &options(10, 1024, 10)).is_err());
    assert_eq!(state.entries_left, 10);
    assert_eq!(state.bytes_left, 0);
    assert!(state.receipts.is_empty());
}

#[test]
fn cancellation_preserves_exact_membership_and_partial_receipt() {
    let root = root_with_file("# Fixture\n");
    let cancel = ScanCancellation::default();
    cancel.cancel();
    let scanner = ConfiguredSecretScanScanner::new(options(10, 1024, 10));
    let output = scanner
        .scan_exact_files(root.path(), &["fixture.env".into()], &cancel)
        .unwrap();
    assert!(!output.scan_errors.is_empty());
    assert_eq!(
        scanner.inspection_receipts()[0]["totals"]["contentBytesReserved"],
        0
    );
    assert_eq!(
        scanner.inspection_receipts()[0]["totals"]["entriesReserved"],
        1
    );
}

#[test]
fn concurrent_roots_cannot_each_spend_the_same_entry_allowance() {
    let first = root_with_file("# Inert first file\n");
    let second = root_with_file("# Inert second file\n");
    let scanner = std::sync::Arc::new(ConfiguredSecretScanScanner::new(options(1, 1024, 10)));
    let paths = [first.path().to_path_buf(), second.path().to_path_buf()];
    let tasks = paths.map(|path| {
        let scanner = std::sync::Arc::clone(&scanner);
        std::thread::spawn(move || {
            scanner.scan_exact_files(&path, &["fixture.env".into()], &ScanCancellation::default())
        })
    });
    let successes = tasks
        .into_iter()
        .map(|task| task.join().unwrap())
        .filter(Result::is_ok)
        .count();
    assert_eq!(successes, 1);
    let receipts = scanner.inspection_receipts();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["totals"]["entriesReserved"], 1);
}
