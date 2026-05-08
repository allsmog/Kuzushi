use super::prelude::*;
use super::*;
use serde_json::json;

#[test]
pub(crate) fn applies_size_binary_and_severity_filters() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("keys.txt"),
        [
            "STRIPE_TEST=sk_test_abcdefghijklmnopqrstuvwxyz",
            "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
        ]
        .join("\n"),
    )
    .unwrap();
    fs::write(temp.path().join("image.bin"), b"\0secret").unwrap();

    let mut options = SecretScanOptions::default();
    options.severity = Some(BTreeSet::from([SecretSeverity::Warning]));
    let report = scan_for_secrets(temp.path(), &options, &ScanCancellation::default()).unwrap();

    assert_eq!(report.files_skipped, 1);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].rule_id, "secret-scan/stripe-test-key");
}

#[test]
pub(crate) fn tool_input_options_coerce_limits_sets_and_severities() {
    let options = SecretScanOptions::from_tool_input(&json!({
        "maxFileBytes": 1,
        "maxFindings": 50_000,
        "excludeDirs": ["build", "  ", "vendor"],
        "binaryExts": ["pem", ".sqlite"],
        "severity": ["ERROR", "WARNING"]
    }))
    .unwrap();

    assert_eq!(options.max_file_bytes, 1024);
    assert_eq!(options.max_findings, 10_000);
    assert!(options.exclude_dirs.contains("build"));
    assert!(options.exclude_dirs.contains("vendor"));
    assert!(options.binary_exts.contains(".pem"));
    assert!(options.binary_exts.contains(".sqlite"));
    assert_eq!(
        options.severity,
        Some(BTreeSet::from([
            SecretSeverity::Error,
            SecretSeverity::Warning
        ]))
    );

    let err = SecretScanOptions::from_tool_input(&json!({"severity": ["BAD"]})).unwrap_err();
    assert!(err.to_string().contains("unknown secret-scan severity"));
}

#[test]
pub(crate) fn secret_severity_and_jwt_shape_helpers_cover_edges() {
    assert_eq!(
        SecretSeverity::try_from("ERROR").unwrap(),
        SecretSeverity::Error
    );
    assert_eq!(
        SecretSeverity::try_from("WARNING").unwrap(),
        SecretSeverity::Warning
    );
    assert_eq!(
        SecretSeverity::try_from("INFO").unwrap(),
        SecretSeverity::Info
    );
    assert!(SecretSeverity::try_from("LOW").is_err());

    assert!(looks_like_jwt(
        "eyJhbGciOiJIUzI1.abcdefghijklmnopqrstuvwxyz.abcdef"
    ));
    assert!(!looks_like_jwt("not.a.jwt"));
    assert!(!looks_like_jwt("eyJshort.payload.sig"));
}

#[test]
pub(crate) fn missing_target_failure_is_actionable() {
    let temp = tempfile::tempdir().unwrap();
    let err = scan_for_secrets(
        &temp.path().join("missing"),
        &SecretScanOptions::default(),
        &ScanCancellation::default(),
    )
    .unwrap_err()
    .to_string();

    assert!(err.contains("secret-scan: target is not a directory"));
}

#[test]
pub(crate) fn scanner_converts_results_to_core_findings() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("keys.txt"),
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGH",
    )
    .unwrap();

    let findings = SecretScanScanner
        .scan(temp.path(), &ScanCancellation::default())
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "secret-scan");
    assert_eq!(findings[0].rule_id, "secret-scan/openai-api-key");
    assert_eq!(findings[0].severity, Severity::High);
}
