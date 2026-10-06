use super::*;

#[test]
fn missing_or_unrelated_scan_evidence_does_not_manufacture_retained_observations() {
    let root = tempfile::tempdir().unwrap();
    let output = json!({"summary":"stopped", "data":{}});
    let record = ToolRunRecord::new(root.path(), "missing", "scan", "sast:scan");
    assert_eq!(attach(record, output.clone()).unwrap(), output);
    let record = ToolRunRecord::new(root.path(), "missing", "scan", "semgrep:scan");
    assert_eq!(attach(record, output.clone()).unwrap(), output);
}

#[test]
fn malformed_phase_evidence_fails_closed_before_terminal_claims() {
    let root = tempfile::tempdir().unwrap();
    write_run_artifact_text(
        root.path(),
        "malformed",
        SAST_PHASE_STAGES_JSONL_FILE,
        "stages",
        "jsonl",
        "{broken}",
    )
    .unwrap();
    let record = ToolRunRecord::new(root.path(), "malformed", "scan", "sast:scan");
    assert!(attach(record, json!({"summary":"stopped", "data":{}}))
        .unwrap_err()
        .to_string()
        .contains("invalid retained Scan phase receipt"));
}
