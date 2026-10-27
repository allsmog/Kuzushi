use super::*;

#[cfg(unix)]
fn executable(folder: &Path, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let binary = folder.join("audit-fixture.sh");
    fs::write(&binary, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    binary
}

fn source(folder: &Path) -> PathBuf {
    let source = folder.join("source");
    fs::create_dir(&source).unwrap();
    fs::write(
        source.join("Cargo.lock"),
        "# Owned inert metadata\nversion = 3\n",
    )
    .unwrap();
    fs::write(
        source.join("rust-toolchain.toml"),
        "# Deliberately invalid; Cargo must never read it\n",
    )
    .unwrap();
    source
}

#[cfg(unix)]
fn package_location_scan(lockfile: &str) -> Vec<Finding> {
    let root = tempfile::tempdir().unwrap();
    let source = source(root.path());
    fs::write(source.join("Cargo.lock"), lockfile).unwrap();
    let output = r#"{"vulnerabilities":{"found":true,"list":[{"advisory":{"id":"RUSTSEC-OWNED","title":"Owned metadata signal"},"package":{"name":"owned","version":"1.0.0"}}]}}"#;
    let binary = executable(
        root.path(),
        &format!("cat >/dev/null; printf '%s' '{output}'"),
    );
    ConfiguredCargoAuditScanner::from_tool_input(&json!({"binary":binary,"offline":true}))
        .unwrap()
        .scan(&source, &ScanCancellation::default())
        .unwrap()
}

#[cfg(unix)]
#[test]
fn cargo_audit_package_location_uses_the_captured_package_declaration() {
    let source = "# Owned café metadata\nversion=3\n[[package]]\nname='other'\nversion='1.0.0'\n\n[[package]]\nname='owned'\nversion='1.0.0'\n";
    let findings = package_location_scan(source);
    assert_eq!(findings[0].start_line, 8);
    assert_eq!(
        findings[0].symbol_locator.as_deref(),
        Some("Cargo.lock#owned@1.0.0")
    );
}

#[cfg(unix)]
#[test]
fn cargo_audit_package_location_is_unavailable_for_missing_or_ambiguous_packages() {
    for source in [
        "version=3\n",
        "version=3\n[[package]]\nname='owned'\nversion='1.0.0'\nsource='one'\n[[package]]\nname='owned'\nversion='1.0.0'\nsource='two'\n",
    ] {
        let findings = package_location_scan(source);
        assert_eq!(findings[0].start_line, 0);
        assert!(findings[0].message.contains("location is unavailable"));
    }
}

#[cfg(unix)]
#[test]
fn cargo_audit_package_location_uses_stdin_even_when_the_live_lockfile_changes() {
    let root = tempfile::tempdir().unwrap();
    let source = source(root.path());
    let original =
        "# Owned captured input\nversion=3\n[[package]]\nname='owned'\nversion='1.0.0'\n";
    fs::write(source.join("Cargo.lock"), original).unwrap();
    let report = r#"{"vulnerabilities":{"found":true,"list":[{"advisory":{"id":"RUSTSEC-OWNED","title":"Owned metadata"},"package":{"name":"owned","version":"1.0.0"}}]}}"#;
    let binary = executable(root.path(), &format!(
        "fixture_root=${{0%/*}}\ncat > \"$fixture_root/captured\"\nprintf 'version=3\\n' > \"$fixture_root/source/Cargo.lock\"\nprintf '%s' '{report}'"
    ));
    let findings =
        ConfiguredCargoAuditScanner::from_tool_input(&json!({"binary":binary,"offline":true}))
            .unwrap()
            .scan(&source, &ScanCancellation::default())
            .unwrap();
    assert_eq!(findings[0].start_line, 4);
    assert_eq!(
        fs::read(root.path().join("captured")).unwrap(),
        original.as_bytes()
    );
    assert_eq!(
        fs::read_to_string(source.join("Cargo.lock")).unwrap(),
        "version=3\n"
    );
}

#[test]
fn cargo_audit_config_refuses_invalid_limits_and_explicit_empty_values() {
    for value in [
        json!({"binary":""}),
        json!({"offline":"false"}),
        json!({"timeoutMs":0}),
        json!({"timeoutMs":config::MAX_TIMEOUT_MS+1}),
        json!({"maxLockfileBytes":0}),
        json!({"maxLockfileBytes":config::MAX_LOCKFILE_BYTES+1}),
    ] {
        assert!(ConfiguredCargoAuditScanner::from_tool_input(&value).is_err());
    }
}

#[test]
fn cargo_audit_missing_cancelled_oversized_and_nonregular_inputs_never_start_a_command() {
    let root = tempfile::tempdir().unwrap();
    let scanner =
        ConfiguredCargoAuditScanner::from_tool_input(&json!({"binary":"missing-audit-fixture"}))
            .unwrap();
    assert!(scanner
        .scan(root.path(), &ScanCancellation::default())
        .unwrap_err()
        .to_string()
        .contains("regular Cargo.lock"));
    fs::create_dir(root.path().join("Cargo.lock")).unwrap();
    assert!(scanner
        .scan(root.path(), &ScanCancellation::default())
        .is_err());
    fs::remove_dir(root.path().join("Cargo.lock")).unwrap();
    fs::write(root.path().join("Cargo.lock"), "x".repeat(128)).unwrap();
    let small =
        ConfiguredCargoAuditScanner::from_tool_input(&json!({"maxLockfileBytes":1})).unwrap();
    assert!(small
        .scan(root.path(), &ScanCancellation::default())
        .is_err());
    let cancel = ScanCancellation::default();
    cancel.cancel();
    let cancelled = ConfiguredCargoAuditScanner::from_tool_input(&json!({})).unwrap();
    assert!(cancelled
        .scan(root.path(), &cancel)
        .unwrap_err()
        .to_string()
        .contains("cancelled"));
    assert_eq!(cancelled.inspection_receipts()[0]["started"], false);
}

#[cfg(unix)]
#[test]
fn cargo_audit_rejects_lockfile_symlinks_inside_and_outside_the_scope() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("real.lock"), "inert metadata").unwrap();
    std::os::unix::fs::symlink(
        root.path().join("real.lock"),
        root.path().join("Cargo.lock"),
    )
    .unwrap();
    let scanner = ConfiguredCargoAuditScanner::from_tool_input(&json!({})).unwrap();
    assert!(scanner
        .scan(root.path(), &ScanCancellation::default())
        .is_err());
    fs::remove_file(root.path().join("Cargo.lock")).unwrap();
    let other = tempfile::NamedTempFile::new().unwrap();
    std::os::unix::fs::symlink(other.path(), root.path().join("Cargo.lock")).unwrap();
    assert!(scanner
        .scan(root.path(), &ScanCancellation::default())
        .is_err());
}

#[cfg(unix)]
#[test]
fn cargo_audit_uses_standalone_binary_captured_stdin_and_an_external_working_directory() {
    let root = tempfile::tempdir().unwrap();
    let source = source(root.path());
    let arguments = root.path().join("arguments");
    let captured = root.path().join("captured");
    let cwd = root.path().join("cwd");
    let binary = executable(root.path(), &format!("pwd > '{}'; printf '%s\\n' \"$@\" > '{}'; cat > '{}'; printf '%s' '{{\"vulnerabilities\":{{\"found\":false}}}}'", cwd.display(), arguments.display(), captured.display()));
    let scanner = ConfiguredCargoAuditScanner::from_tool_input(&json!({"binary":binary,"offline":true,"allowStale":true,"advisoryDb":root.path(),"timeoutMs":1000})).unwrap();
    assert!(scanner
        .scan(&source, &ScanCancellation::default())
        .unwrap()
        .is_empty());
    assert_eq!(
        fs::read(&captured).unwrap(),
        fs::read(source.join("Cargo.lock")).unwrap()
    );
    assert!(!fs::read_to_string(cwd)
        .unwrap()
        .trim()
        .starts_with(source.to_str().unwrap()));
    let args = fs::read_to_string(arguments).unwrap();
    assert!(args.contains("audit\n--json\n--file\n-\n"));
    assert!(args.contains("--no-fetch\n--no-yanked\n"));
    assert!(args.contains("--stale"));
    assert_eq!(
        scanner.inspection_receipts()[0]["capturedLockfiles"][0]["bytes"],
        35
    );
}

#[cfg(unix)]
#[test]
fn cargo_audit_deadline_is_shared_across_roots_and_malformed_output_is_not_clean() {
    let root = tempfile::tempdir().unwrap();
    let source = source(root.path());
    let binary = executable(root.path(), "cat >/dev/null; sleep 20");
    let scanner =
        ConfiguredCargoAuditScanner::from_tool_input(&json!({"binary":binary,"timeoutMs":50}))
            .unwrap();
    let started = Instant::now();
    assert!(scanner
        .scan(&source, &ScanCancellation::default())
        .unwrap_err()
        .to_string()
        .contains("deadline"));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(scanner
        .scan(&source, &ScanCancellation::default())
        .unwrap_err()
        .to_string()
        .contains("no further process"));
    let binary = executable(root.path(), "cat >/dev/null; printf '%s' '{invalid}'");
    let scanner = ConfiguredCargoAuditScanner::from_tool_input(&json!({"binary":binary})).unwrap();
    assert!(scanner
        .scan(&source, &ScanCancellation::default())
        .unwrap_err()
        .to_string()
        .contains("malformed"));
}

#[test]
fn cargo_audit_scope_rebinding_preserves_root_identity_and_separates_independent_lockfiles() {
    let mut finding = Finding::new_tool(
        "cargo-audit",
        "RUSTSEC-OWNED",
        "Cargo.lock",
        1,
        None,
        Severity::Medium,
        "owned metadata",
    )
    .with_structural_locator("Cargo.lock#owned@1.0.0");
    let root_identity = finding.fingerprint.clone();
    rebind_audit_finding(&mut finding, "Cargo.lock".into());
    assert_eq!(finding.fingerprint, root_identity);
    let mut second = finding.clone();
    rebind_audit_finding(&mut finding, "a/Cargo.lock".into());
    rebind_audit_finding(&mut second, "b/Cargo.lock".into());
    assert_ne!(finding.fingerprint, second.fingerprint);
    assert_eq!(
        second.symbol_locator.as_deref(),
        Some("b/Cargo.lock#owned@1.0.0")
    );
}

#[cfg(unix)]
#[test]
fn cargo_audit_inflight_cancellation_stops_process_work_without_a_report() {
    let root = tempfile::tempdir().unwrap();
    let source = source(root.path());
    let binary = executable(root.path(), "cat >/dev/null; sleep 20");
    let scanner =
        ConfiguredCargoAuditScanner::from_tool_input(&json!({"binary":binary,"timeoutMs":3000}))
            .unwrap();
    let cancel = ScanCancellation::default();
    let trigger = cancel.clone();
    let worker = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(80));
        trigger.cancel();
    });
    let started = Instant::now();
    let error = scanner.scan(&source, &cancel).unwrap_err();
    worker.join().unwrap();
    assert!(error.to_string().contains("cancel"), "{error:#}");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(
        scanner.inspection_receipts()[0]["capturedLockfiles"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
