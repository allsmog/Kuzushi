use super::*;

fn root_with_file() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    let content = format!("FROM owned:latest\nUSER root\n# {}", "x".repeat(800));
    std::fs::write(root.path().join("Dockerfile"), content).unwrap();
    root
}

#[test]
fn directory_roots_share_content_and_entry_limits() {
    let first = root_with_file();
    let second = root_with_file();
    let scanner = ConfiguredIacScanScanner::new(IacScanOptions {
        max_total_bytes: 2048,
        max_entries: 2,
        ..Default::default()
    });
    let cancel = ScanCancellation::default();
    scanner.scan_artifacts(first.path(), &cancel).unwrap();
    scanner.scan_artifacts(second.path(), &cancel).unwrap();
    let receipts = scanner.inspection_receipts();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[1]["configuredLimits"]["maxTotalBytes"], 2048);
    assert_eq!(receipts[1]["sharedJobAllowance"]["entriesUsed"], 2);
    assert_eq!(receipts[1]["sharedJobAllowance"]["bytesRead"], 1660);
    let uninspected = scanner.scan_artifacts(first.path(), &cancel).unwrap();
    assert!(uninspected.findings.is_empty());
    assert!(uninspected.scan_errors[0].contains("shared inspection allowance exhausted"));
}

#[test]
fn cancelled_enumeration_holds_unresolved_allowance() {
    let root = root_with_file();
    let scanner = ConfiguredIacScanScanner::new(IacScanOptions::default());
    let cancel = ScanCancellation::default();
    cancel.cancel();
    assert!(scanner.scan_artifacts(root.path(), &cancel).is_err());
    let receipts = scanner.inspection_receipts();
    assert_eq!(receipts[0]["status"], "incomplete");
    assert_eq!(receipts[0]["unresolvedAllowance"]["maxEntries"], 100_000);
    let uninspected = scanner
        .scan_artifacts(root.path(), &ScanCancellation::default())
        .unwrap();
    assert!(uninspected.findings.is_empty() && !uninspected.scan_errors.is_empty());
    assert_eq!(scanner.inspection_receipts().len(), 2);
}

#[test]
fn empty_partial_results_are_not_a_clean_legacy_result() {
    let root = root_with_file();
    std::fs::write(root.path().join("Dockerfile"), "#".repeat(2048)).unwrap();
    let scanner = ConfiguredIacScanScanner::new(IacScanOptions {
        max_file_bytes: 1024,
        ..Default::default()
    });
    assert!(scanner
        .scan(root.path(), &ScanCancellation::default())
        .is_err());
    assert!(!scanner.supports_exact_files());
}
