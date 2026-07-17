use super::*;
use crate::{ScanCancellation, Severity};
use serde_json::json;
use std::{collections::BTreeSet, fs};

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
        "maxFileBytes": 12_345,
        "maxFindings": 9_999,
        "excludeDirs": ["build", "  ", "vendor"],
        "binaryExts": ["pem", ".sqlite"],
        "severity": ["ERROR", "WARNING"]
    }))
    .unwrap();

    assert_eq!(options.max_file_bytes, 12_345);
    assert_eq!(options.max_findings, 9_999);
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
pub(crate) fn tool_input_rejects_limits_instead_of_silently_rewriting_them() {
    for value in [json!(-1), json!(0), json!(1), json!(67_108_865_u64)] {
        let error = SecretScanOptions::from_tool_input(&json!({"maxFileBytes": value}))
            .unwrap_err()
            .to_string();
        assert!(error.contains("maxFileBytes must be"), "{error}");
    }

    for value in [json!(-1), json!(0), json!(10_001)] {
        let error = SecretScanOptions::from_tool_input(&json!({"maxFindings": value}))
            .unwrap_err()
            .to_string();
        assert!(error.contains("maxFindings must be"), "{error}");
    }
}

#[test]
pub(crate) fn custom_file_limit_changes_the_executed_scan() {
    let temp = tempfile::tempdir().unwrap();
    let secret = "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGH";
    fs::write(
        temp.path().join("large.env"),
        format!("{secret}\n{}", "x".repeat(2_000)),
    )
    .unwrap();

    let limited = SecretScanOptions::from_tool_input(&json!({"maxFileBytes": 1024})).unwrap();
    let limited_report =
        scan_for_secrets(temp.path(), &limited, &ScanCancellation::default()).unwrap();
    assert!(limited_report.findings.is_empty());
    assert_eq!(limited_report.files_skipped, 1);

    let custom = SecretScanOptions::from_tool_input(&json!({"maxFileBytes": 12_345})).unwrap();
    let custom_report =
        scan_for_secrets(temp.path(), &custom, &ScanCancellation::default()).unwrap();
    assert_eq!(custom_report.findings.len(), 1);
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
    assert_eq!(
        findings[0].static_proof_state,
        Some(StaticProofState::SignalOnly)
    );
}
