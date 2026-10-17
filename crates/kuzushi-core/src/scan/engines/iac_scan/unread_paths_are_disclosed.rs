use super::*;
use crate::ScanCancellation;

/// A directory the walk cannot list used to return `Ok(())`, so its whole
/// subtree left no trace in the report. A missing directory drives the same
/// `read_dir` failure without depending on the test process's permissions.
#[test]
fn an_unlistable_directory_is_recorded_rather_than_read_as_empty() {
    let temp = tempfile::tempdir().unwrap();
    let mut files = Vec::new();
    let mut gaps = CoverageGaps::default();

    collect_iac_files(
        temp.path(),
        &temp.path().join("infra"),
        &IacScanOptions::default(),
        &mut files,
        &mut gaps,
    )
    .unwrap();

    assert!(files.is_empty());
    assert_eq!(gaps.total(), 1);
    assert_eq!(gaps.gaps[0].kind, CoverageGapKind::Directory);
    assert_eq!(gaps.gaps[0].path, "infra");
}

#[test]
fn a_fully_read_tree_discloses_no_gap() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Dockerfile"),
        "FROM node:latest\nUSER root\n",
    )
    .unwrap();

    let report = scan_iac(
        temp.path(),
        &IacScanOptions::default(),
        &ScanCancellation::default(),
    )
    .unwrap();

    assert_eq!(report.files_scanned, 1);
    assert!(report.coverage_gaps.is_empty());
    assert!(!report.output().contains("Unread paths"));
}

#[test]
fn a_gap_reaches_both_the_output_and_the_tool_json() {
    let temp = tempfile::tempdir().unwrap();
    let mut files = Vec::new();
    let mut coverage_gaps = CoverageGaps::default();
    collect_iac_files(
        temp.path(),
        &temp.path().join("infra"),
        &IacScanOptions::default(),
        &mut files,
        &mut coverage_gaps,
    )
    .unwrap();
    let report = IacScanReport {
        target: temp.path().display().to_string(),
        kind: IacScanOptions::default().kind,
        findings: Vec::new(),
        files_scanned: 0,
        inspected_files: None,
        files_skipped: 0,
        coverage_gaps,
        inspection: IacInspection::default(),
    };

    let output = report.output();
    assert!(
        output.contains("Unread paths: 1 (coverage is incomplete)"),
        "{output}"
    );
    assert!(output.contains("- directory infra: "), "{output}");

    let json = report.to_tool_json();
    assert_eq!(json["data"]["coverageGaps"]["gaps"][0]["path"], "infra");
    assert_eq!(json["data"]["coverageGaps"]["gaps"][0]["kind"], "directory");
}

/// `kuzushi scan` reads coverage only from `ScanEngineOutput::scan_errors`.
/// The default `scan_artifacts` forwards findings alone, which would let the
/// umbrella run report a partially read target as complete.
#[test]
fn the_scan_engine_forwards_gaps_as_aggregate_scan_errors() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Dockerfile"),
        "FROM node:latest\nUSER root\n",
    )
    .unwrap();

    let output = IacScanScanner::default()
        .scan_artifacts(temp.path(), &ScanCancellation::default())
        .unwrap();

    assert!(!output.findings.is_empty());
    assert!(output.scan_errors.is_empty());
    assert!(output.codeql_sarif_documents.is_empty());
}

/// The mapping the engine hands the aggregate channel, over a gap the walk
/// recorded. An unread path has to arrive as an unanalyzed part, not as the
/// silence that reads as full coverage.
#[test]
fn a_recorded_gap_becomes_an_unanalyzed_part() {
    let temp = tempfile::tempdir().unwrap();
    let mut files = Vec::new();
    let mut gaps = CoverageGaps::default();
    collect_iac_files(
        temp.path(),
        &temp.path().join("infra"),
        &IacScanOptions::default(),
        &mut files,
        &mut gaps,
    )
    .unwrap();

    let scan_errors = gaps.scan_error_lines();

    assert_eq!(scan_errors.len(), 1);
    assert!(
        scan_errors[0].starts_with("unread directory infra: "),
        "{scan_errors:?}"
    );
}
