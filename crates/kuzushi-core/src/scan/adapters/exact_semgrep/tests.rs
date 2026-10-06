use super::*;

#[test]
fn exact_semgrep_arguments_are_literal_files_without_a_directory_target() {
    let scanner = SemgrepScanner {
        binary: "semgrep".into(),
        config: vec!["rules.yml".into()],
    };
    let files = vec![
        "app/[route].py".into(),
        "root file.py".into(),
        "-literal.py".into(),
    ];
    let command = scanner.semgrep_command_for_files(Path::new("/repo"), &files);
    let arguments = command
        .get_args()
        .map(|value| value.to_string_lossy().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        &arguments[arguments.len() - 4..],
        &["--", "app/[route].py", "root file.py", "-literal.py"]
    );
    assert!(!arguments.iter().any(|value| value == "."));
    assert_eq!(command.get_current_dir(), Some(Path::new("/repo")));
}

#[test]
fn missing_exact_semgrep_process_is_partial_without_claiming_selected_files_clean() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("a.py"), "print(1)\n").unwrap();
    fs::write(root.path().join("b.py"), "print(2)\n").unwrap();
    let scanner = SemgrepScanner {
        binary: "/missing/exact-semgrep".into(),
        config: vec!["rules.yml".into()],
    };
    let files = vec!["a.py".into(), "b.py".into()];
    let output = scanner
        .scan_exact_source_files(root.path(), &files, &ScanCancellation::default())
        .unwrap();
    assert!(output.findings.is_empty());
    assert_eq!(output.scan_errors.len(), 1);
    assert!(output.scan_errors[0].contains("2 selected files"));
}

#[cfg(unix)]
fn batch_fixture(stop: &str) -> (tempfile::TempDir, SemgrepScanner, Vec<String>) {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let files = (0..129)
        .map(|index| format!("file-{index:03}.py"))
        .collect::<Vec<_>>();
    for file in &files {
        fs::write(root.path().join(file), "print('Labeled test input')\n").unwrap();
    }
    let binary = root.path().join("scanner-fixture.sh");
    let first = json!({"results":[{"check_id":"labeled.fixture","path":"file-000.py","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":"Labeled test observation","severity":"WARNING"}}],"paths":{"scanned":&files[..64]}});
    fs::write(
        root.path().join("first-batch.json"),
        serde_json::to_vec(&first).unwrap(),
    )
    .unwrap();
    fs::write(&binary, format!("#!/bin/sh\necho called >> .fixture-calls\nif [ $(wc -l < .fixture-calls) -gt 1 ]; then\n{stop}\nfi\ncat first-batch.json\n")).unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    let scanner = SemgrepScanner {
        binary: binary.display().to_string(),
        config: vec!["labeled-fixture".into()],
    };
    (root, scanner, files)
}

#[cfg(unix)]
#[test]
fn exact_semgrep_keeps_completed_batches_and_never_starts_work_after_failure() {
    let (root, scanner, files) = batch_fixture("echo 'labeled second-batch failure' >&2; exit 2");
    let output = scanner
        .scan_exact_source_files(root.path(), &files, &Default::default())
        .unwrap();
    assert_eq!(output.findings.len(), 1);
    assert_eq!(output.findings[0].file_path, "file-000.py");
    assert_eq!(output.scan_errors.len(), 1);
    assert!(output.scan_errors[0].contains("65 selected files"));
    assert_eq!(
        fs::read_to_string(root.path().join(".fixture-calls"))
            .unwrap()
            .lines()
            .count(),
        2
    );
}

#[test]
fn exact_semgrep_rechecks_regular_file_membership_before_starting_a_process() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("replaced.py")).unwrap();
    let scanner = SemgrepScanner {
        binary: "/missing/process-must-not-start".into(),
        config: vec!["unused".into()],
    };
    let output = scanner
        .scan_exact_source_files(root.path(), &["replaced.py".into()], &Default::default())
        .unwrap();
    assert!(output.findings.is_empty());
    assert!(output.scan_errors[0].contains("requires regular files"));
    assert!(!output.scan_errors[0].contains("could not start"));
}
