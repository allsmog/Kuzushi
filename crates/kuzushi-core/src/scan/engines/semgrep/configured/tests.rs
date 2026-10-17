use super::*;

#[test]
fn semgrep_scan_workers_default_to_one_and_reject_invalid_direct_inputs() {
    let scanner = ConfiguredSemgrepScanner::from_tool_input(&json!({})).unwrap();
    assert_eq!(
        scanner.inspection_receipts()[0]["configuredLimits"]["jobs"],
        1
    );
    assert_eq!(
        scanner.inspection_receipts()[0]["excludedPaths"],
        json!(["**/.kuzushi/**"])
    );
    let scanner = ConfiguredSemgrepScanner::from_tool_input(&json!({"jobs":4})).unwrap();
    assert_eq!(
        scanner.inspection_receipts()[0]["configuredLimits"]["jobs"],
        4
    );
    for value in [json!(0), json!(-1), json!(257), json!("4"), json!(null)] {
        assert!(ConfiguredSemgrepScanner::from_tool_input(&json!({"jobs":value})).is_err());
    }
}

#[cfg(unix)]
#[test]
fn configured_semgrep_workers_reach_the_actual_process_arguments() {
    let (root,mut scanner)=scanner_fixture("printf '%s\\n' \"$@\" > ../args; printf '{\"results\":[],\"paths\":{\"scanned\":[\"notice.py\"]}}'",3000);
    scanner.jobs = 4;
    scanner
        .scan_exact_files(
            &root.path().join("source"),
            &["notice.py".into()],
            &Default::default(),
        )
        .unwrap();
    let args = fs::read_to_string(root.path().join("args")).unwrap();
    assert!(args
        .lines()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| pair == ["--jobs", "4"]));
}

#[test]
fn semgrep_time_allowance_is_explicit_positive_and_bounded() {
    let scanner = ConfiguredSemgrepScanner::from_tool_input(&json!({})).unwrap();
    assert_eq!(
        scanner.timeout.as_millis(),
        DEFAULT_SEMGREP_JOB_TIMEOUT_MS as u128
    );
    for value in [
        json!(0),
        json!(-1),
        json!(MAX_SEMGREP_JOB_TIMEOUT_MS + 1),
        json!("20"),
    ] {
        assert!(ConfiguredSemgrepScanner::from_tool_input(&json!({"timeoutMs":value})).is_err());
    }
    let scanner = ConfiguredSemgrepScanner::from_tool_input(&json!({"timeout_ms":100})).unwrap();
    assert_eq!(scanner.timeout, Duration::from_millis(100));
}

#[cfg(unix)]
fn scanner_fixture(body: &str, timeout_ms: u64) -> (tempfile::TempDir, ConfiguredSemgrepScanner) {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("source")).unwrap();
    fs::write(
        root.path().join("source/notice.py"),
        "print('Labeled policy fixture')\n",
    )
    .unwrap();
    let binary = root.path().join("scanner.sh");
    fs::write(&binary, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    let scanner = ConfiguredSemgrepScanner::from_tool_input(&json!({
        "binary":binary,"config":"labeled-test-rule","timeoutMs":timeout_ms,
    }))
    .unwrap();
    (root, scanner)
}

#[cfg(unix)]
#[test]
fn semgrep_deadline_does_not_reset_for_another_root() {
    let (root, scanner) = scanner_fixture("printf called >> ../calls; sleep 60", 1000);
    let second_root = root.path().join("second-source");
    fs::create_dir(&second_root).unwrap();
    let started = Instant::now();
    let error = scanner
        .scan_outcome_with_cancel(&second_root, &Default::default())
        .unwrap_err();
    assert!(error.to_string().contains("deadline"), "{error:#}");
    assert!(started.elapsed() < Duration::from_secs(5));
    let error = scanner
        .scan_outcome_with_cancel(&root.path().join("source"), &Default::default())
        .unwrap_err();
    assert!(error.to_string().contains("no further process started"));
    let calls = match fs::read_to_string(root.path().join("calls")) {
        Ok(calls) => calls,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => panic!("Cannot inspect scanner starts: {error}"),
    };
    // The deadline may stop startup before the fixture writes its first marker.
    assert!(calls.is_empty() || calls == "called", "{calls}");
}

#[cfg(unix)]
#[test]
fn semgrep_cancellation_stops_running_work_without_a_clean_result() {
    let (root, scanner) = scanner_fixture("printf called >> ../calls; sleep 60", 10_000);
    let cancel = ScanCancellation::default();
    let trigger = cancel.clone();
    let marker = root.path().join("calls");
    let started_marker = marker.clone();
    let worker = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !started_marker.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        trigger.cancel();
    });
    let started = Instant::now();
    let error = scanner
        .scan_outcome_with_cancel(&root.path().join("source"), &cancel)
        .unwrap_err();
    worker.join().unwrap();
    assert!(marker.exists(), "scanner fixture never started");
    assert!(error.to_string().contains("cancel"), "{error:#}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[cfg(unix)]
#[test]
fn semgrep_timeout_retains_finished_file_batches_and_never_starts_a_third() {
    let body = r#"printf 'called\n' >> ../calls
if [ $(wc -l < ../calls) -gt 1 ]; then sleep 60; fi
printf '{"results":[{"check_id":"labeled.policy","path":"file-000.py","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":"Labeled policy observation","severity":"INFO"}}],"paths":{"scanned":['
selected=0
separator=''
for member in "$@"; do
  if [ "$selected" = 1 ]; then
    printf '%s"%s"' "$separator" "$member"
    separator=','
  elif [ "$member" = '--' ]; then
    selected=1
  fi
done
printf ']}}'
"#;
    let (root, mut scanner) = scanner_fixture(body, 3000);
    // Argument pressure keeps the first completed batch small under parallel tests.
    scanner.scanner.config = vec!["c".repeat(11000)];
    let files = (0..2050)
        .map(|i| format!("file-{i:03}.py"))
        .collect::<Vec<_>>();
    for file in &files {
        fs::write(
            root.path().join("source").join(file),
            "print('Labeled policy fixture')\n",
        )
        .unwrap();
    }
    let output = scanner
        .scan_exact_files(&root.path().join("source"), &files, &Default::default())
        .unwrap();
    assert_eq!(output.findings.len(), 1, "{:?}", output.scan_errors);
    assert!(
        output
            .scan_errors
            .iter()
            .any(|e| e.contains("deadline") && e.contains("selected files")),
        "{:?}",
        output.scan_errors
    );
    assert_eq!(
        fs::read_to_string(root.path().join("calls"))
            .unwrap()
            .lines()
            .count(),
        2
    );
}
