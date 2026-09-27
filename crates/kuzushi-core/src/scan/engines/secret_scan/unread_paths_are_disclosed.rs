use super::*;
use crate::ScanCancellation;
use std::fs;

/// A directory the walk cannot list used to return `Ok(())`, so its whole
/// subtree left no trace: no findings, no `filesScanned`, no `filesSkipped`.
/// A missing directory drives the same `read_dir` failure without depending on
/// the test process's permissions.
#[test]
fn an_unlistable_directory_is_recorded_rather_than_read_as_empty() {
    let temp = tempfile::tempdir().unwrap();
    let mut files = Vec::new();
    let mut gaps = CoverageGaps::default();

    collect_files(
        temp.path(),
        &temp.path().join("vanished"),
        &SecretScanOptions::default(),
        &mut files,
        &mut gaps,
    )
    .unwrap();

    assert!(files.is_empty());
    assert_eq!(gaps.total(), 1);
    assert_eq!(gaps.gaps[0].kind, CoverageGapKind::Directory);
    assert_eq!(gaps.gaps[0].path, "vanished");
}

#[test]
fn a_fully_read_tree_discloses_no_gap() {
    // No credential shape here on purpose: this test is about coverage
    // accounting, and the leak fixtures the secret gate approves live under
    // `tests/fixtures/secret-scan/leaks/`.
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("src")).unwrap();
    fs::write(temp.path().join("src/config.env"), "LOG_LEVEL=debug\n").unwrap();

    let report = scan_for_secrets(
        temp.path(),
        &SecretScanOptions::default(),
        &ScanCancellation::default(),
    )
    .unwrap();

    assert_eq!(report.files_scanned, 1);
    assert!(report.coverage_gaps.is_empty());
    assert!(!report.output().contains("Unread paths"));
    assert_eq!(
        report.to_tool_json()["data"]["coverageGaps"]["gaps"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
}

#[test]
fn a_gap_reaches_both_the_output_and_the_tool_json() {
    let report = report_with_unreadable_directory();

    let output = report.output();
    assert!(output.contains("Unread paths: 1 (coverage is incomplete)"), "{output}");
    assert!(output.contains("- directory config: "), "{output}");

    let json = report.to_tool_json();
    assert_eq!(json["data"]["coverageGaps"]["gaps"][0]["path"], "config");
    assert_eq!(
        json["data"]["coverageGaps"]["gaps"][0]["kind"],
        "directory"
    );
    assert_eq!(json["data"]["coverageGaps"]["unnamed"], 0);
}

/// A report is still a `0 findings` report when a directory went unread, so
/// the summary line alone must not be taken as a cleared tree.
#[test]
fn a_clean_finding_count_coexists_with_an_unread_path() {
    let report = report_with_unreadable_directory();

    let output = report.output();
    assert!(output.starts_with("secret-scan: 0 findings (no secrets detected)"));
    assert_eq!(report.coverage_gaps.total(), 1);
}

fn report_with_unreadable_directory() -> SecretScanReport {
    let temp = tempfile::tempdir().unwrap();
    let mut files = Vec::new();
    let mut coverage_gaps = CoverageGaps::default();
    collect_files(
        temp.path(),
        &temp.path().join("config"),
        &SecretScanOptions::default(),
        &mut files,
        &mut coverage_gaps,
    )
    .unwrap();

    SecretScanReport {
        target: temp.path().display().to_string(),
        findings: Vec::new(),
        files_scanned: 0,
        files_skipped: 0,
        coverage_gaps,
    }
}
