use super::*;

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    for name in ["root file.env", "excluded.env", "-literal.env"] {
        std::fs::write(
            root.path().join(name),
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
        )
        .unwrap();
    }
    root
}

#[test]
fn exact_secret_membership_keeps_literal_root_files_and_excludes_other_source() {
    let root = fixture();
    let report = scan_for_secrets_in_files(
        root.path(),
        &["root file.env".into(), "-literal.env".into()],
        &Default::default(),
    )
    .unwrap();
    assert_eq!(report.files_scanned, 2);
    assert_eq!(report.findings.len(), 2);
    assert!(report.coverage_gaps.is_empty());
    assert!(report
        .findings
        .iter()
        .all(|finding| finding.file_path != "excluded.env"));
}

#[test]
fn exact_secret_finding_cap_discloses_unsearched_files_and_possible_additional_matches() {
    let root = fixture();
    let options = SecretScanOptions {
        max_findings: 1,
        ..Default::default()
    };
    let report = scan_exact_files_with_options(
        root.path(),
        &["root file.env".into(), "-literal.env".into()],
        &options,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(report.files_scanned, 1);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.coverage_gaps.total(), 1);
    assert!(report.coverage_gaps.gaps[0]
        .reason
        .contains("1 selected files"));
    let report = scan_exact_files_with_options(
        root.path(),
        &["root file.env".into()],
        &options,
        &Default::default(),
    )
    .unwrap();
    assert!(report.coverage_gaps.gaps[0]
        .reason
        .contains("0 selected files"));
    assert!(report.coverage_gaps.gaps[0]
        .reason
        .contains("further matches"));
}

#[test]
fn exact_secret_cancellation_records_no_clean_coverage() {
    let root = fixture();
    let cancellation = ScanCancellation::default();
    cancellation.cancel();
    let report =
        scan_for_secrets_in_files(root.path(), &["root file.env".into()], &cancellation).unwrap();
    assert_eq!(report.files_scanned, 0);
    assert!(report.findings.is_empty());
    assert!(report.coverage_gaps.gaps[0].reason.contains("canceled"));
}

#[test]
fn exact_secret_discovery_refuses_directory_membership() {
    let root = fixture();
    std::fs::create_dir(root.path().join("directory")).unwrap();
    assert!(
        scan_for_secrets_in_files(root.path(), &["directory".into()], &Default::default()).is_err()
    );
}
