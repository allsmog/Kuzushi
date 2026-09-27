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
    fs::write(temp.path().join("Dockerfile"), "FROM node:latest\nUSER root\n").unwrap();

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
        files_skipped: 0,
        coverage_gaps,
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
